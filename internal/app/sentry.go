package app

// func SetupSentry() {
// 	if err := sentry.Init(sentry.ClientOptions{
// 		Dsn:              env.String("SENTRY_DSN"),
// 		Debug:            env.IsDebug(),
// 		EnableTracing:    true,
// 		TracesSampleRate: 1.0,
// 		ServerName:       env.String("APP_NAME"),
// 		Release:          Version(),
// 		Environment:      env.Name(),
// 	}); err != nil {
// 		//sentry.CaptureException(err)
// 		slog.Error("Sentry initialization failed", slog.Any("error", err))
// 	}
// }
