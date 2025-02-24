using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text;

namespace nClam;

public class ActivityHelper
{

  internal const string ActivitySourceName = "nClam";
  internal static ActivitySource ActivitySource = new ActivitySource(ActivitySourceName, typeof(ClamClient).Assembly.GetName().Version.ToString());
  internal static Meter Meter = new Meter(ActivitySourceName, typeof(ClamClient).Assembly.GetName().Version.ToString());
  internal static Histogram<double> ScanningCount = Meter.CreateHistogram<double>("nclam.scanner", unit: "Seconds", description: "Virus scan meter");

  internal static void BeginClamCommandExecute(string command, ClamClient client)
  {

    if (!ActivitySource.HasListeners()) return;

    using var activity = ActivitySource.StartActivity("ExecuteClamCommandAsync", ActivityKind.Client);
    activity?.SetTag("Command", command);
    activity?.SetTag("Server", client.ServerName);
    activity?.SetTag("Port", client.Port);
    if (activity is not null)
    {

      var displayCommand = command switch
      {
        "SCAN" or "INSTREAM" => "Scan",
        "MULTISCAN" => "Multiple File Scan",
        _ => command
      };
      activity.DisplayName = $"ClamAV {displayCommand}";
    }


  }

}


public static class Extensions {

  public static IHostApplicationBuilder AddNClamAntivirus(this IHostApplicationBuilder builder)
  {

    builder.Services.AddOpenTelemetry()
               .WithTracing(t =>
               {
                 t.AddSource(ActivityHelper.ActivitySourceName);
                 // This ensures the core Redis instrumentation services from OpenTelemetry.Instrumentation.StackExchangeRedis are added
                 //t.ConfigureNClamInstrumentation();
                 // This ensures that any logic performed by the AddInstrumentation method is executed (this is usually called by AddRedisInstrumentation())
                 // t.AddInstrumentation(sp => sp.GetRequiredService<StackExchangeRedisInstrumentation>());
               });

    return builder;

  }

}
