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

// listGcpAdminReportsLoginActivities liste les activités "login"
// Elle gère les qualifiers : time (via StartTime/EndTime), actor_email, ip_address, event_names.
func listGcpAdminReportsLoginActivities(ctx context.Context, d *plugin.QueryData, _ *plugin.HydrateData) (interface{}, error) {
    // Création du service Reports API
    service, err := ReportsService(ctx, d)
    if err != nil {
        plugin.Logger(ctx).Error("gcp_admin_reports_login_activity.list", "service_error", err)
        return nil, err
    }

    call := service.Activities.List("all", "login")

    // 1. Gestion de la plage temporelle
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
                    endTime = t
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


    // 3. Pagination
    pageToken := ""
    const apiMaxPageSize = 1000
    // Déterminer taille de la première page
    var initialPageSize int64 = apiMaxPageSize
    if d.QueryContext.Limit != nil {
        limit := *d.QueryContext.Limit
        if limit < initialPageSize {
            initialPageSize = limit
        }
    }
    call.MaxResults(initialPageSize)

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
                d.StreamListItem(ctx, activity)
                if d.RowsRemaining(ctx) == 0 {
                    return nil, nil
                }
            }
        }
        if resp.NextPageToken == "" {
            break
        }
        pageToken = resp.NextPageToken
        // Ajuster la taille pour la prochaine page selon la limite SQL restante
        if d.QueryContext.Limit != nil {
            remaining := d.RowsRemaining(ctx)
            if remaining > 0 && remaining < apiMaxPageSize {
                call.MaxResults(int64(remaining))
            } else {
                call.MaxResults(apiMaxPageSize)
            }
        } else {
            call.MaxResults(apiMaxPageSize)
        }
    }

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