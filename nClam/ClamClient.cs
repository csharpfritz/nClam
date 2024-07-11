namespace nClam
{
	using Microsoft.Extensions.Logging;
	using Microsoft.Extensions.Logging.Abstractions;
	using System;
	using System.Buffers;
	using System.Diagnostics;
	using System.Diagnostics.Metrics;
	using System.IO;
	using System.Linq;
	using System.Net;
	using System.Net.Sockets;
	using System.Reflection;
	using System.Text;
	using System.Threading;
	using System.Threading.Tasks;

	public class ClamClient : IClamClient
	{

		public const string ActivitySourceName = "nClam";
		private readonly ILogger<ClamClient> Logger;
		static ActivitySource ActivitySource = new ActivitySource(ActivitySourceName, typeof(ClamClient).Assembly.GetName().Version.ToString());
		static Meter Meter = new Meter(ActivitySourceName, typeof(ClamClient).Assembly.GetName().Version.ToString());
		static Counter<long> ScannerCounter = Meter.CreateCounter<long>("nclam.scanner.scan_count");
		static Counter<long> FoundVirusCounter = Meter.CreateCounter<long>("nclam.scanner.found_count");
		static Histogram<long> ScanningCount = Meter.CreateHistogram<long>("nclam.scanner.duration", description: "Virus scan duration");

		/// <summary>
		/// Maximum size (in bytes) which streams will be broken up to when sending to the ClamAV server.  Used in the SendAndScanFile methods.  128kb is the default size.
		/// </summary>
		public int MaxChunkSize { get; set; }

		/// <summary>
		/// Maximum size (in bytes) that can be streamed to the ClamAV server before it will terminate the connection. Used in the SendAndScanFile methods. 25mb is the default size.
		/// </summary>
		public long MaxStreamSize { get; set; }

		/// <summary>
		/// Address to the ClamAV server
		/// </summary>
		public string? Server { get; set; }

		/// <summary>
		/// IP Address to the ClamAV server
		/// </summary>
		public IPAddress? ServerIP { get; set; }

		/// <summary>
		/// Port which the ClamAV server is listening on
		/// </summary>
		public int Port { get; set; }

		private ClamClient(ILogger<ClamClient> logger = null!)
		{

			this.Logger = logger ?? NullLogger<ClamClient>.Instance;

			MaxChunkSize = 131072; //128k
			MaxStreamSize = 26214400; //25mb
		}

		/// <summary>
		/// A class to connect to a ClamAV server and request virus scans
		/// </summary>
		/// <param name="server">Address to the ClamAV server</param>
		/// <param name="port">Port which the ClamAV server is listening on</param>
		public ClamClient(string server, int port = 3310, ILogger<ClamClient> logger = null!) : this(logger)
		{
			Server = server;
			Port = port;
		}

		/// <summary>
		/// A class to connect to a ClamAV server via IP and request virus scans
		/// </summary>
		/// <param name="serverIP">IP Address to the ClamAV server</param>
		/// <param name="port">Port which the ClamAV server is listening on</param>
		public ClamClient(IPAddress serverIP, int port = 3310, ILogger<ClamClient> logger = null!) : this(logger)
		{
			ServerIP = serverIP;
			Port = port;
		}

		/// <summary>
		/// Helper method which connects to the ClamAV Server, performs the command and returns the result.
		/// </summary>
		/// <param name="command">The command to execute on the ClamAV Server</param>
		/// <param name="cancellationToken">cancellation token used in requests</param>
		/// <param name="additionalCommand">Action to define additional server communications.  Executed after the command is sent and before the response is read.</param>
		/// <returns>The full response from the ClamAV server.</returns>
		private async Task<string> ExecuteClamCommandAsync(string command, CancellationToken cancellationToken, Func<Stream, CancellationToken, Task>? additionalCommand = null)
		{

			var stopWatch = System.Diagnostics.Stopwatch.StartNew();

			string result = string.Empty;

			var clam = new TcpClient(AddressFamily.InterNetwork);

			using var activity = ActivitySource.StartActivity("ExecuteClamCommandAsync", ActivityKind.Client);
			activity?.SetTag("Command", command);
			activity?.SetTag("Server", ServerIP?.ToString() ?? Server);
			activity?.SetTag("Port", Port);
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

			var scanEvents = new string[] { "SCAN", "INSTREAM", "MULTISCAN" };
			if (ScannerCounter.Enabled && scanEvents.Contains(command))
			{
				ScannerCounter.Add(1);
			}

			try
			{
				Logger.LogDebug($"Connecting to ClamAV server at {ServerIP?.ToString() ?? Server}:{Port}");
				using var stream = await CreateConnection(clam).ConfigureAwait(false);
				Logger.LogDebug($"Connected to ClamAV server at {ServerIP?.ToString() ?? Server}:{Port}");

				var commandText = $"z{command}\0";
				var commandBytes = Encoding.UTF8.GetBytes(commandText);
				Logger.LogInformation($"Executing command {command}");
				activity?.AddEvent(new ActivityEvent($"Executing command {command}"));

				await stream.WriteAsync(commandBytes, 0, commandBytes.Length, cancellationToken).ConfigureAwait(false);

				if (additionalCommand != null)
				{
					await additionalCommand(stream, cancellationToken).ConfigureAwait(false);
				}

				using var reader = new StreamReader(stream);
				result = await reader.ReadToEndAsync().ConfigureAwait(false);
				activity?.AddEvent(new ActivityEvent($"Completed command {command}"));

				if (!String.IsNullOrEmpty(result))
				{
					//if we have a result, trim off the terminating null character
					result = result.TrimEnd('\0');
				}
			} catch (Exception ex)
			{
				activity?.SetStatus(ActivityStatusCode.Error, $"Error scanning: {ex.Message}");
			}
			finally
			{
				if (clam.Connected)
				{
					Logger.LogDebug($"Closed connection to ClamAV server at {ServerIP?.ToString() ?? Server}:{Port}");
					clam.Close();
				}
			}

			stopWatch.Stop();
			ScanningCount.Record(stopWatch.ElapsedMilliseconds);
			Logger.LogDebug("Command {0} took: {1}", command, stopWatch.Elapsed);
			System.Diagnostics.Debug.WriteLine("Command {0} took: {1}", command, stopWatch.Elapsed);


			if (FoundVirusCounter.Enabled && result.EndsWith("found", StringComparison.InvariantCultureIgnoreCase))
			{
				FoundVirusCounter.Add(1);
			}

			return result;
		}

		/// <summary>
		/// Helper method to send a byte array over the wire to the ClamAV server, split up in chunks.
		/// </summary>
		/// <param name="sourceData">The stream to send to the ClamAV server.</param>
		/// <param name="clamStream">The communication channel to the ClamAV server.</param>
		/// <param name="cancellationToken"></param>
		private async Task SendStreamFileChunksAsync(Stream sourceData, Stream clamStream, CancellationToken cancellationToken)
		{
			var streamSize = 0;
			int readByteCount;
			var bytes = new byte[MaxChunkSize];

			while ((readByteCount = await sourceData.ReadAsync(bytes, 0, MaxChunkSize, cancellationToken).ConfigureAwait(false)) > 0)
			{
				streamSize += readByteCount;

				if (streamSize > MaxStreamSize)
				{
					throw new MaxStreamSizeExceededException(MaxStreamSize);
				}

				var readBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(readByteCount));  //convert readByteCount to NetworkOrder!
				await clamStream.WriteAsync(readBytes, 0, readBytes.Length, cancellationToken).ConfigureAwait(false);
				await clamStream.WriteAsync(bytes, 0, readByteCount, cancellationToken).ConfigureAwait(false);
			}

			var newMessage = BitConverter.GetBytes(0);
			await clamStream.WriteAsync(newMessage, 0, newMessage.Length, cancellationToken).ConfigureAwait(false);
		}
#if NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Helper method to send a memory region over the wire to the ClamAV server, split up in chunks.
        /// </summary>
        /// <param name="sourceData">The stream to send to the ClamAV server.</param>
        /// <param name="clamStream">The communication channel to the ClamAV server.</param>
        /// <param name="cancellationToken"></param>
        private async Task SendStreamFileChunksAsync(ReadOnlyMemory<byte> sourceData, Stream clamStream, CancellationToken cancellationToken)
        {
            var readByteCount = 0;

            if (sourceData.Length > MaxStreamSize)
            {
                throw new MaxStreamSizeExceededException(MaxStreamSize);
            }

            while (readByteCount < sourceData.Length)
            {
                var toRead = ((sourceData.Length - readByteCount) > MaxChunkSize ? MaxChunkSize : sourceData.Length - readByteCount);
                var readBytes = BitConverter.GetBytes((uint) System.Net.IPAddress.HostToNetworkOrder(toRead));

                await clamStream.WriteAsync(readBytes, 0, readBytes.Length, cancellationToken).ConfigureAwait(false);
                await clamStream.WriteAsync(sourceData.Slice(readByteCount, toRead), cancellationToken).ConfigureAwait(false);

                readByteCount += toRead;
            }

            await clamStream.WriteAsync(BitConverter.GetBytes(0));
        }
#endif
		protected async virtual Task<Stream> CreateConnection(TcpClient clam)
		{
			await (ServerIP == null ? clam.ConnectAsync(Server, Port) : clam.ConnectAsync(ServerIP, Port)).ConfigureAwait(false);

			return clam.GetStream();
		}

		/// <summary>
		/// Gets the ClamAV server version
		/// </summary>
		public Task<string> GetVersionAsync()
		{
			return GetVersionAsync(CancellationToken.None);
		}

		/// <summary>
		/// Gets the ClamAV server version
		/// </summary>
		public async Task<string> GetVersionAsync(CancellationToken cancellationToken)
		{
			var version = await ExecuteClamCommandAsync("VERSION", cancellationToken).ConfigureAwait(false);

			return version;
		}

		/// <summary>
		/// Gets the ClamAV server stats
		/// </summary>
		public Task<string> GetStatsAsync()
		{
			return GetStatsAsync(CancellationToken.None);
		}

		/// <summary>
		/// Gets the ClamAV server stats
		/// </summary>
		public async Task<string> GetStatsAsync(CancellationToken cancellationToken)
		{
			var stats = await ExecuteClamCommandAsync("STATS", cancellationToken).ConfigureAwait(false);

			return stats;
		}

		/// <summary>
		/// Executes a PING command on the ClamAV server.
		/// <para>Tip:when you call this method , please wrap your call in a try/catch ,because if return is not true,will throw a exception,or you can use <see cref="TryPingAsync"/></para>
		/// </summary>
		/// <returns>If the server responds with PONG, returns true.  Otherwise throw a exception.</returns>
		public Task<bool> PingAsync()
		{
			return PingAsync(CancellationToken.None);
		}

		/// <summary>
		/// Executes a PING command on the ClamAV server.
		/// <para>Tip:when you call this method , please wrap your call in a try/catch ,because if return is not true,will throw a exception,or you can use <see cref="TryPingAsync"/></para>
		/// </summary>
		/// <returns>If the server responds with PONG, returns true.  Otherwise throw a exception.</returns>
		public async Task<bool> PingAsync(CancellationToken cancellationToken)
		{
			var result = await ExecuteClamCommandAsync("PING", cancellationToken).ConfigureAwait(false);
			return result.ToLowerInvariant() == "pong";
		}

		/// <summary>
		/// Executes a PING command on the ClamAV server.
		/// </summary>
		/// <returns>If the server responds with PONG, returns true.  Otherwise returns false.</returns>
		public Task<bool> TryPingAsync()
		{
			return TryPingAsync(CancellationToken.None);
		}

		/// <summary>
		/// Executes a PING command on the ClamAV server.
		/// </summary>
		/// <returns>If the server responds with PONG, returns true.  Otherwise returns false.</returns>
		public async Task<bool> TryPingAsync(CancellationToken cancellationToken)
		{
			try
			{
				var result = await ExecuteClamCommandAsync("PING", cancellationToken).ConfigureAwait(false);
				return result.ToLowerInvariant() == "pong";
			}
			catch
			{
				return false;
			}
		}
		/// <summary>
		/// Scans a file/directory on the ClamAV Server.
		/// </summary>
		/// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
		public Task<ClamScanResult> ScanFileOnServerAsync(string filePath)
		{
			return ScanFileOnServerAsync(filePath, CancellationToken.None);
		}

		/// <summary>
		/// Scans a file/directory on the ClamAV Server.
		/// </summary>
		/// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
		/// <param name="cancellationToken">cancellation token used for request</param>
		public async Task<ClamScanResult> ScanFileOnServerAsync(string filePath, CancellationToken cancellationToken)
		{
			return new ClamScanResult(await ExecuteClamCommandAsync($"SCAN {filePath}", cancellationToken).ConfigureAwait(false));
		}

		/// <summary>
		/// Scans a file/directory on the ClamAV Server using multiple threads on the server.
		/// </summary>
		/// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
		public Task<ClamScanResult> ScanFileOnServerMultithreadedAsync(string filePath)
		{
			return ScanFileOnServerMultithreadedAsync(filePath, CancellationToken.None);
		}

		/// <summary>
		/// Scans a file/directory on the ClamAV Server using multiple threads on the server.
		/// </summary>
		/// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
		/// <param name="cancellationToken">cancellation token used for request</param>
		public async Task<ClamScanResult> ScanFileOnServerMultithreadedAsync(string filePath, CancellationToken cancellationToken)
		{
			return new ClamScanResult(await ExecuteClamCommandAsync($"MULTISCAN {filePath}", cancellationToken).ConfigureAwait(false));
		}

		/// <summary>
		/// Sends the data to the ClamAV server as a stream.
		/// </summary>
		/// <param name="fileData">Byte array containing the data from a file.</param>
		/// <returns></returns>
		public Task<ClamScanResult> SendAndScanFileAsync(byte[] fileData)
		{
			return SendAndScanFileAsync(fileData, CancellationToken.None);
		}

		/// <summary>
		/// Sends the data to the ClamAV server as a stream.
		/// </summary>
		/// <param name="fileData">Byte array containing the data from a file.</param>
		/// <param name="cancellationToken">cancellation token used for request</param>
		/// <returns></returns>
		public async Task<ClamScanResult> SendAndScanFileAsync(byte[] fileData, CancellationToken cancellationToken)
		{
			var sourceStream = new MemoryStream(fileData);
			return new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)).ConfigureAwait(false));
		}

		/// <summary>
		/// Sends the data to the ClamAV server as a stream.
		/// </summary>
		/// <param name="sourceStream">Stream containing the data to scan.</param>
		/// <returns></returns>
		public Task<ClamScanResult> SendAndScanFileAsync(Stream sourceStream)
		{
			return SendAndScanFileAsync(sourceStream, CancellationToken.None);
		}

#if NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// Sends the data to the ClamAV server as a ReadOnlyMemory<byte> block, as returned by PipeReader.ReadAsync()
        /// </summary>
        /// <param name="fileData">Memory region that contains the data read from the file.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns></returns>
        public async Task<ClamScanResult> SendAndScanFileAsync(ReadOnlyMemory<byte> fileData, CancellationToken cancellationToken)
        {
            return new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(fileData, stream, token)).ConfigureAwait(false));
        }

        /// <summary>
        /// Sends the data to the ClamAV server as a chunk
        /// </summary>
        /// <param name="sourceData">Stream containing the data to scan.</param>
        /// <returns></returns>
        public Task<ClamScanResult> SendAndScanFileAsync(ReadOnlyMemory<byte> sourceData)
        {
            return SendAndScanFileAsync(sourceData, CancellationToken.None);
        }
#endif

		/// <summary>
		/// Sends the data to the ClamAV server as a stream.
		/// </summary>
		/// <param name="sourceStream">Stream containing the data to scan.</param>
		/// <param name="cancellationToken">cancellation token used for request</param>
		/// <returns></returns>
		public async Task<ClamScanResult> SendAndScanFileAsync(Stream sourceStream, CancellationToken cancellationToken)
		{
			var result = new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)).ConfigureAwait(false));
			switch (result.Result)
			{
				case ClamScanResults.Clean:
					Logger.LogInformation("No virus detected in stream");
					break;
				case ClamScanResults.Error:
					Logger.LogWarning($"Error while scanning stream");
					break;
				case ClamScanResults.VirusDetected:
					if (result.InfectedFiles != null && result.InfectedFiles.Any())
					{
						foreach (var file in result.InfectedFiles)
						{
							Logger.LogWarning($"Virus '{file.VirusName.Trim()}' detected in '{file.FileName}'");
						}
					} else {
						Logger.LogWarning($"Virus detected in stream");
					}
					break;
			}
			return result;
		}

		/// <summary>
		/// Reads the file from the path and then sends it to the ClamAV server as a stream.
		/// </summary>
		/// <param name="filePath">Path to the file/directory.</param>
		public async Task<ClamScanResult> SendAndScanFileAsync(string filePath)
		{
			using var stream = File.OpenRead(filePath);
			return await SendAndScanFileAsync(stream).ConfigureAwait(false);
		}

		/// <summary>
		/// Reads the file from the path and then sends it to the ClamAV server as a stream.
		/// </summary>
		/// <param name="filePath">Path to the file/directory.</param>
		/// <param name="cancellationToken">cancellation token used for request</param>
		public async Task<ClamScanResult> SendAndScanFileAsync(string filePath, CancellationToken cancellationToken)
		{
			using var stream = File.OpenRead(filePath);
			return await SendAndScanFileAsync(stream, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Shuts down the ClamAV server in an orderly fashion.
		/// </summary>
		public async Task Shutdown(CancellationToken cancellationToken)
		{
			await ExecuteClamCommandAsync("SHUTDOWN", cancellationToken).ConfigureAwait(false);
		}
	}
}
