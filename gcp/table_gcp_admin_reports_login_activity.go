package gcp

import (
	"context"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
	adminreports "google.golang.org/api/admin/reports/v1"
)

// tableGcpAdminReportsLoginActivity définit la table Steampipe pour l’Admin Reports API, activités “login”.
func tableGcpAdminReportsLoginActivity(ctx context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "gcp_admin_reports_login_activity",
		Description: "GCP Admin Reports API - activité de connexion (login)",
		Get: &plugin.GetConfig{
			KeyColumns: plugin.AllColumns([]string{"time", "unique_qualifier", "actor_email"}),
			Hydrate:    getGcpAdminReportsLoginActivity,
			Tags:       map[string]string{"service": "admin", "product": "reports", "action": "activities.get"},
		},
		List: &plugin.ListConfig{
			Hydrate: listGcpAdminReportsLoginActivities,
			KeyColumns: plugin.KeyColumnSlice{
				{Name: "time", Require: plugin.Optional, Operators: []string{">", ">=", "<", "<=", "="}},
				{Name: "actor_email", Require: plugin.Optional},
				{Name: "ip_address", Require: plugin.Optional},
				{Name: "event_name", Require: plugin.Optional},
			},
			Tags: map[string]string{"service": "admin", "product": "reports", "action": "activities.list"},
		},
		Columns: []*plugin.Column{
			{
				Name:        "time",
				Description: "Horodatage de l'activité (ID.Time) au format RFC3339",
				Type:        proto.ColumnType_TIMESTAMP,
				Transform:   transform.FromField("Id.Time"),
			},
			{
				Name:        "actor_email",
				Description: "Adresse email de l'acteur (Actor.Email)",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Actor.Email"),
			},
			{
    			Name:        "event_name",
    			Description: "Nom de l’événement (ex: login_success)",
    			Type:        proto.ColumnType_STRING,
    			Transform:   transform.FromField("Events").Transform(extractFirstEventName),
			},
			{
				Name:        "unique_qualifier",
				Description: "Identifiant unique qualifiant cette activité (ID.UniqueQualifier)",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Id.UniqueQualifier"),
			},
			{
				Name:        "application_name",
				Description: "Nom de l’application du rapport (ici toujours 'login')",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Id.ApplicationName"),
			},
			{
				Name:        "actor_profile_id",
				Description: "Profile ID de l'acteur (Actor.ProfileId)",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Actor.ProfileId"),
			},
			{
				Name:        "actor_caller_type",
				Description: "Type de caller (Actor.CallerType)",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Actor.CallerType"),
			},
			{
				Name:        "ip_address",
				Description: "Adresse IP associée à l’activité (IpAddress)",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("IpAddress"),
			},
			{
				Name:        "events",
				Description: "Liste des événements détaillés (Events) pour cette activité, en JSON",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Events"),
			},
			{
				Name:        "title",
				Description: "Titre de l’activité (Time + Actor Email)",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromField("Id.Time").Transform(convertTimeToString).Transform(formatTitleWithActorEmail),
			},
			{
				Name:        "tags",
				Description: "Tags pour classification (liste des noms d’événements)",
				Type:        proto.ColumnType_JSON,
				Transform:   transform.FromField("Events").Transform(extractEventNames),
			},
			{
				Name:        "location",
				Description: "Constante 'global'",
				Type:        proto.ColumnType_STRING,
				Transform:   transform.FromConstant("global"),
			},
			{
				Name:        "project",
				Description: "Constante 'global' ou domaine, car non lié à un projet GCP",
				Type:        proto.ColumnType_STRING,
				Hydrate:     getConstantGlobal,
				Transform:   transform.FromValue(),
			},
		},
	}
}

func extractFirstEventName(_ context.Context, d *transform.TransformData) (interface{}, error) {
    // d.Value est de type []*adminreports.ActivityEvents
    events, ok := d.Value.([]*adminreports.ActivityEvents)
    if !ok || len(events) == 0 {
        return "", nil
    }
    return events[0].Name, nil
}


//// HYDRATE FUNCTIONS

// listGcpAdminReportsLoginActivities liste les activités "login" et stoppe après 500 items maximum.
// Elle gère les qualifiers : time (via StartTime/EndTime), actor_email, ip_address, event_names.
func listGcpAdminReportsLoginActivities(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	// Créer le service Reports API
	service, err := ReportsService(ctx, d)
	if err != nil {
		plugin.Logger(ctx).Error("gcp_admin_reports_login_activity.list", "service_error", err)
		return nil, err
	}

	call := service.Activities.List("all", "login")

	// Nous voulons caper à 500 résultats max
	const maxTotalResults = 500

	// Calculer pageSize initial : on peut demander jusqu'à maxTotalResults en une page
	pageSize := maxTotalResults
	// Si l'utilisateur a mis une limite Steampipe plus petite, la respecter
	if d.QueryContext.Limit != nil {
		limit := *d.QueryContext.Limit
		if limit < int64(pageSize) {
			pageSize = int(limit)
		}
	}
	// L'API attend un int64 pour MaxResults
	call.MaxResults(int64(pageSize))

	// Déterminer startTime / endTime à partir des qualifiers "time"
	now := time.Now()
	startTime := now.Add(-180 * 24 * time.Hour)
	endTime := now
	if quals := d.Quals["time"]; quals != nil {
		for _, q := range quals.Quals {
			if q.Value != nil && q.Value.GetTimestampValue() != nil {
				t := q.Value.GetTimestampValue().AsTime()
				switch q.Operator {
				case "=":
					startTime = t
					endTime = t
				case ">":
					startTime = t.Add(time.Nanosecond)
				case ">=":
					startTime = t
				case "<":
					endTime = t.Add(-time.Nanosecond)
				case "<=":
					endTime = t
				}
			}
		}
	}
	if !startTime.After(endTime) {
		call.StartTime(startTime.Format(time.RFC3339))
		call.EndTime(endTime.Format(time.RFC3339))
	} else {
		return nil, nil
	}

	// Qualifier actor_email
	if quals := d.Quals["actor_email"]; quals != nil {
		for _, q := range quals.Quals {
			if q.Value != nil && q.Value.GetStringValue() != "" {
				filter := "actor.email==" + "\"" + q.Value.GetStringValue() + "\""
				call.Filters(filter)
				break
			}
		}
	}
	// Qualifier ip_address
	if quals := d.Quals["ip_address"]; quals != nil {
		for _, q := range quals.Quals {
			if q.Value != nil && q.Value.GetStringValue() != "" {
				filter := "ipAddress==" + "\"" + q.Value.GetStringValue() + "\""
				call.Filters(filter)
				break
			}
		}
	}
	// Qualifier event_names
	if quals := d.Quals["event_names"]; quals != nil {
		for _, q := range quals.Quals {
			if q.Value != nil && q.Value.GetStringValue() != "" {
				filter := "events.name==" + "\"" + q.Value.GetStringValue() + "\""
				call.Filters(filter)
				break
			}
		}
	}

	// Pagination avec compteur
	var totalCount int
	pageToken := ""
	for {
		if pageToken != "" {
			call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			plugin.Logger(ctx).Error("gcp_admin_reports_login_activity.list", "api_error", err)
			return nil, err
		}
		if resp.Items != nil {
			for _, activity := range resp.Items {
				// Stream l’item
				d.StreamListItem(ctx, activity)
				totalCount++
				// Si on a atteint le maximum à renvoyer, on stoppe
				if totalCount >= maxTotalResults {
					return nil, nil
				}
				// Si Steampipe indique une limite SQL plus petite, on la respecte
				if d.RowsRemaining(ctx) == 0 {
					return nil, nil
				}
			}
		}
		// Si pas de page suivante, sortir
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
		// Ajuster la pageSize pour la page suivante selon le nombre restant pour atteindre 500
		remaining := maxTotalResults - totalCount
		if remaining <= 0 {
			break
		}
		// Prendre le min entre remaining et la limite Steampipe ou la taille précédente
		nextPageSize := remaining
		if d.QueryContext.Limit != nil {
			limit := *d.QueryContext.Limit
			// Si limit-totalCount plus petit que remaining, on utilise limit-totalCount
			if int64(nextPageSize) > limit-int64(totalCount) {
				nextPageSize = int(limit - int64(totalCount))
			}
			if nextPageSize <= 0 {
				break
			}
		}
		// Définir pour la requête suivante
		call.MaxResults(int64(nextPageSize))
	}
	return nil, nil
}

// getGcpAdminReportsLoginActivity .
func getGcpAdminReportsLoginActivity(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	return nil, nil
}

//// TRANSFORM FUNCTIONS 
func extractEventNames(_ context.Context, d *transform.TransformData) (interface{}, error) {
	activity, ok := d.HydrateItem.(*adminreports.Activity)
	if !ok {
		return nil, nil
	}
	if activity.Events == nil {
		return nil, nil
	}
	names := []string{}
	for _, e := range activity.Events {
		if e.Name != "" {
			names = append(names, e.Name)
		}
	}
	return names, nil
}

func convertTimeToString(_ context.Context, d *transform.TransformData) (interface{}, error) {
	activity, ok := d.HydrateItem.(*adminreports.Activity)
	if !ok {
		return "", nil
	}
	if activity.Id == nil || activity.Id.Time == "" {
		return "", nil
	}
	return activity.Id.Time, nil
}

func formatTitleWithActorEmail(_ context.Context, d *transform.TransformData) (interface{}, error) {
	timeStr, ok := d.Value.(string)
	if !ok {
		return nil, nil
	}
	activity, ok := d.HydrateItem.(*adminreports.Activity)
	if !ok {
		return timeStr, nil
	}
	if activity.Actor == nil || activity.Actor.Email == "" {
		return timeStr, nil
	}
	return timeStr + " - " + activity.Actor.Email, nil
}

func getConstantGlobal(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
	return "global", nil
}
