package com.example.honeypotmanagement.service;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.enums.Severity;
import com.example.honeypotmanagement.model.AttackEvent;
import com.example.honeypotmanagement.repo.AttackEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class DatabaseHoneypotService {

    private final AttackDetectionService attackDetectionService;
    private final GeoLocationService geoLocationService;
    private final AttackEventRepository attackEventRepository;

    // Thread pools for handling connections
    private final ExecutorService mysqlExecutor = Executors.newCachedThreadPool(new DatabaseThreadFactory("MySQL"));
    private final ExecutorService postgresExecutor = Executors.newCachedThreadPool(new DatabaseThreadFactory("PostgreSQL"));

    // Server sockets
    private ServerSocket mysqlSocket;
    private ServerSocket postgresSocket;

    // Service state
    private volatile boolean mysqlRunning = false;
    private volatile boolean postgresRunning = false;

    // Connection counters
    private final AtomicInteger mysqlConnections = new AtomicInteger(0);
    private final AtomicInteger postgresConnections = new AtomicInteger(0);

    @EventListener(ApplicationReadyEvent.class)
    public void startDatabaseHoneypots() {
        log.info("🗄️ Starting Database Honeypot Services...");

        // Start MySQL honeypot on port 3307 (avoiding conflict with real MySQL on 3306)
        mysqlExecutor.submit(this::runMySQLHoneypot);

        // Start PostgreSQL honeypot on port 5433 (avoiding conflict with real PostgreSQL on 5432)
        postgresExecutor.submit(this::runPostgreSQLHoneypot);
    }

    // ==============================================================================
    // MYSQL HONEYPOT IMPLEMENTATION
    // ==============================================================================

    private void runMySQLHoneypot() {
        try {
            mysqlSocket = new ServerSocket(3307);
            mysqlRunning = true;
            log.info("🗄️ MySQL Honeypot started on port 3307");

            while (!mysqlSocket.isClosed() && mysqlRunning) {
                try {
                    Socket clientSocket = mysqlSocket.accept();
                    mysqlConnections.incrementAndGet();
                    mysqlExecutor.submit(() -> handleMySQLConnection(clientSocket));
                } catch (IOException e) {
                    if (mysqlRunning) {
                        log.error("Error accepting MySQL connection: ", e);
                    }
                }
            }
        } catch (IOException e) {
            if (mysqlRunning) {
                log.error("MySQL Honeypot error: ", e);
            }
        } finally {
            mysqlRunning = false;
            log.info("MySQL Honeypot stopped");
        }
    }

    private void handleMySQLConnection(Socket clientSocket) {
        String clientIP = clientSocket.getInetAddress().getHostAddress();
        int connectionId = mysqlConnections.get();

        log.info("MySQL connection attempt #{} from: {}", connectionId, clientIP);

        try {
            // Send MySQL handshake packet
            sendMySQLHandshake(clientSocket, connectionId);

            // Read client authentication packet
            byte[] authPacket = readMySQLPacket(clientSocket);
            if (authPacket != null && authPacket.length > 0) {
                MySQLAuthInfo authInfo = parseMySQLAuth(authPacket);

                log.info("MySQL auth attempt from {} - User: {}, Database: {}, Client: {}",
                        clientIP, authInfo.username, authInfo.database, authInfo.clientFlags);

                // Record the attack
                recordDatabaseAttack(clientIP, "MySQL:3307",
                        String.format("User: %s, Database: %s, Capabilities: %s",
                                authInfo.username, authInfo.database, authInfo.clientFlags),
                        "MySQL authentication attempt");

                // Send authentication error
                sendMySQLError(clientSocket, 1045, "28000",
                        String.format("Access denied for user '%s'@'%s' (using password: %s)",
                                authInfo.username, clientIP, authInfo.hasPassword ? "YES" : "NO"));

                // Keep connection alive briefly to seem realistic
                Thread.sleep(1000);
            }

        } catch (Exception e) {
            log.debug("MySQL client {} disconnected: {}", clientIP, e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                log.debug("Error closing MySQL client socket: ", e);
            }
            mysqlConnections.decrementAndGet();
        }
    }

    private void sendMySQLHandshake(Socket socket, int connectionId) throws IOException {
        // MySQL Protocol Version 10 handshake packet
        byte[] serverVersion = "8.0.28-honeypot\0".getBytes(StandardCharsets.UTF_8);
        byte[] authPluginData1 = generateRandomBytes(8);
        byte[] authPluginData2 = generateRandomBytes(12);
        byte[] authPluginName = "mysql_native_password\0".getBytes(StandardCharsets.UTF_8);

        // Calculate packet length
        int packetLength = 1 + 4 + serverVersion.length + 1 + 2 + 1 + 2 + 2 + 1 + 10 +
                authPluginData1.length + 1 + authPluginData2.length + authPluginName.length;

        ByteBuffer buffer = ByteBuffer.allocate(packetLength + 4);

        // Packet header
        buffer.put((byte) (packetLength & 0xFF));
        buffer.put((byte) ((packetLength >> 8) & 0xFF));
        buffer.put((byte) ((packetLength >> 16) & 0xFF));
        buffer.put((byte) 0); // Packet sequence

        // Handshake packet
        buffer.put((byte) 10); // Protocol version
        buffer.put(serverVersion);
        buffer.putInt(Integer.reverseBytes(connectionId)); // Connection ID
        buffer.put(authPluginData1);
        buffer.put((byte) 0); // Filler

        // Server capabilities (lower 2 bytes)
        buffer.putShort(Short.reverseBytes((short) 0xF7FF));

        // Character set
        buffer.put((byte) 0x21); // utf8_general_ci

        // Status flags
        buffer.putShort(Short.reverseBytes((short) 0x0002));

        // Server capabilities (upper 2 bytes)
        buffer.putShort(Short.reverseBytes((short) 0x8001));

        // Auth plugin data length
        buffer.put((byte) (authPluginData1.length + authPluginData2.length + 1));

        // Reserved bytes
        buffer.put(new byte[10]);

        // Auth plugin data part 2
        buffer.put(authPluginData2);
        buffer.put((byte) 0);

        // Auth plugin name
        buffer.put(authPluginName);

        socket.getOutputStream().write(buffer.array());
        socket.getOutputStream().flush();
    }

    private byte[] readMySQLPacket(Socket socket) throws IOException {
        byte[] header = new byte[4];
        int bytesRead = socket.getInputStream().read(header);

        if (bytesRead != 4) {
            return null;
        }

        int packetLength = (header[0] & 0xFF) | ((header[1] & 0xFF) << 8) | ((header[2] & 0xFF) << 16);

        if (packetLength > 0 && packetLength < 16777215) { // Max MySQL packet size
            byte[] packet = new byte[packetLength];
            bytesRead = socket.getInputStream().read(packet);
            return bytesRead == packetLength ? packet : null;
        }

        return null;
    }

    private MySQLAuthInfo parseMySQLAuth(byte[] packet) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(packet);

            // Skip client capabilities (4 bytes)
            int clientFlags = buffer.getInt();

            // Skip max packet size (4 bytes)
            buffer.getInt();

            // Skip charset (1 byte)
            buffer.get();

            // Skip reserved bytes (23 bytes)
            buffer.position(buffer.position() + 23);

            // Read username (null-terminated)
            StringBuilder username = new StringBuilder();
            byte b;
            while (buffer.hasRemaining() && (b = buffer.get()) != 0) {
                username.append((char) b);
            }

            // Read password length
            boolean hasPassword = false;
            if (buffer.hasRemaining()) {
                int passwordLength = buffer.get() & 0xFF;
                hasPassword = passwordLength > 0;
                // Skip password bytes
                buffer.position(Math.min(buffer.position() + passwordLength, buffer.limit()));
            }

            // Read database name (null-terminated)
            StringBuilder database = new StringBuilder();
            while (buffer.hasRemaining() && (b = buffer.get()) != 0) {
                database.append((char) b);
            }

            return new MySQLAuthInfo(username.toString(), database.toString(), hasPassword, clientFlags);

        } catch (Exception e) {
            return new MySQLAuthInfo("unknown", "", false, 0);
        }
    }

    private void sendMySQLError(Socket socket, int errorCode, String sqlState, String message) throws IOException {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] sqlStateBytes = sqlState.getBytes(StandardCharsets.UTF_8);

        int packetLength = 1 + 2 + 1 + sqlStateBytes.length + messageBytes.length;

        ByteBuffer buffer = ByteBuffer.allocate(packetLength + 4);

        // Packet header
        buffer.put((byte) (packetLength & 0xFF));
        buffer.put((byte) ((packetLength >> 8) & 0xFF));
        buffer.put((byte) ((packetLength >> 16) & 0xFF));
        buffer.put((byte) 2); // Packet sequence

        // Error packet
        buffer.put((byte) 0xFF); // Error packet marker
        buffer.putShort(Short.reverseBytes((short) errorCode));
        buffer.put((byte) '#'); // SQL state marker
        buffer.put(sqlStateBytes);
        buffer.put(messageBytes);

        socket.getOutputStream().write(buffer.array());
        socket.getOutputStream().flush();
    }

    // ==============================================================================
    // POSTGRESQL HONEYPOT IMPLEMENTATION
    // ==============================================================================

    private void runPostgreSQLHoneypot() {
        try {
            postgresSocket = new ServerSocket(5433);
            postgresRunning = true;
            log.info("🐘 PostgreSQL Honeypot started on port 5433");

            while (!postgresSocket.isClosed() && postgresRunning) {
                try {
                    Socket clientSocket = postgresSocket.accept();
                    postgresConnections.incrementAndGet();
                    postgresExecutor.submit(() -> handlePostgreSQLConnection(clientSocket));
                } catch (IOException e) {
                    if (postgresRunning) {
                        log.error("Error accepting PostgreSQL connection: ", e);
                    }
                }
            }
        } catch (IOException e) {
            if (postgresRunning) {
                log.error("PostgreSQL Honeypot error: ", e);
            }
        } finally {
            postgresRunning = false;
            log.info("PostgreSQL Honeypot stopped");
        }
    }

    private void handlePostgreSQLConnection(Socket clientSocket) {
        String clientIP = clientSocket.getInetAddress().getHostAddress();
        int connectionId = postgresConnections.get();

        log.info("PostgreSQL connection attempt #{} from: {}", connectionId, clientIP);

        try {
            // Read PostgreSQL startup message
            byte[] startupMessage = readPostgreSQLMessage(clientSocket);

            if (startupMessage != null && startupMessage.length > 0) {
                PostgreSQLStartupInfo startupInfo = parsePostgreSQLStartup(startupMessage);

                log.info("PostgreSQL startup from {} - User: {}, Database: {}, Version: {}",
                        clientIP, startupInfo.user, startupInfo.database, startupInfo.protocolVersion);

                // Record the attack
                recordDatabaseAttack(clientIP, "PostgreSQL:5433",
                        String.format("User: %s, Database: %s, Protocol: %d",
                                startupInfo.user, startupInfo.database, startupInfo.protocolVersion),
                        "PostgreSQL connection attempt");

                // Send authentication request (MD5 password)
                sendPostgreSQLAuthRequest(clientSocket);

                // Read password response
                byte[] passwordMessage = readPostgreSQLMessage(clientSocket);
                if (passwordMessage != null) {
                    String passwordData = parsePostgreSQLPassword(passwordMessage);

                    recordDatabaseAttack(clientIP, "PostgreSQL:5433",
                            String.format("Password attempt for user %s", startupInfo.user),
                            "PostgreSQL password authentication");

                    // Send authentication failure
                    sendPostgreSQLError(clientSocket, "28P01",
                            String.format("password authentication failed for user \"%s\"", startupInfo.user));
                }
            }

        } catch (Exception e) {
            log.debug("PostgreSQL client {} disconnected: {}", clientIP, e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                log.debug("Error closing PostgreSQL client socket: ", e);
            }
            postgresConnections.decrementAndGet();
        }
    }

    private byte[] readPostgreSQLMessage(Socket socket) throws IOException {
        // Read message length (first 4 bytes)
        byte[] lengthBytes = new byte[4];
        int bytesRead = socket.getInputStream().read(lengthBytes);

        if (bytesRead != 4) {
            return null;
        }

        int messageLength = ByteBuffer.wrap(lengthBytes).getInt();

        if (messageLength > 4 && messageLength < 1000000) { // Reasonable size limit
            byte[] message = new byte[messageLength];
            System.arraycopy(lengthBytes, 0, message, 0, 4);

            int remaining = messageLength - 4;
            int totalRead = 0;

            while (totalRead < remaining) {
                int read = socket.getInputStream().read(message, 4 + totalRead, remaining - totalRead);
                if (read == -1) break;
                totalRead += read;
            }

            return totalRead == remaining ? message : null;
        }

        return null;
    }

    private PostgreSQLStartupInfo parsePostgreSQLStartup(byte[] message) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(message);

            // Skip length (4 bytes)
            buffer.getInt();

            // Read protocol version
            int protocolVersion = buffer.getInt();

            String user = "";
            String database = "";

            // Parse parameters
            while (buffer.hasRemaining()) {
                String key = readPostgreSQLString(buffer);
                if (key.isEmpty()) break;

                String value = readPostgreSQLString(buffer);

                switch (key) {
                    case "user":
                        user = value;
                        break;
                    case "database":
                        database = value;
                        break;
                }
            }

            return new PostgreSQLStartupInfo(user, database, protocolVersion);

        } catch (Exception e) {
            return new PostgreSQLStartupInfo("unknown", "unknown", 0);
        }
    }

    private String readPostgreSQLString(ByteBuffer buffer) {
        StringBuilder sb = new StringBuilder();
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            if (b == 0) break;
            sb.append((char) b);
        }
        return sb.toString();
    }

    private void sendPostgreSQLAuthRequest(Socket socket) throws IOException {
        // Authentication request for MD5 password
        ByteBuffer buffer = ByteBuffer.allocate(12);

        buffer.put((byte) 'R'); // Authentication request
        buffer.putInt(12); // Message length
        buffer.putInt(5); // MD5 password authentication
        buffer.put(generateRandomBytes(4)); // Salt for MD5

        socket.getOutputStream().write(buffer.array());
        socket.getOutputStream().flush();
    }

    private String parsePostgreSQLPassword(byte[] message) {
        try {
            // Skip message type (1 byte) and length (4 bytes)
            String password = new String(message, 5, message.length - 5, StandardCharsets.UTF_8);
            return password.replace("\0", ""); // Remove null terminators
        } catch (Exception e) {
            return "unknown";
        }
    }

    private void sendPostgreSQLError(Socket socket, String sqlState, String message) throws IOException {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        int totalLength = 1 + 4 + 1 + 5 + 1 + messageBytes.length + 1 + 1;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);

        buffer.put((byte) 'E'); // Error response
        buffer.putInt(totalLength - 1); // Message length (excluding type byte)
        buffer.put((byte) 'C'); // Error code field
        buffer.put(sqlState.getBytes(StandardCharsets.UTF_8));
        buffer.put((byte) 0);
        buffer.put((byte) 'M'); // Message field
        buffer.put(messageBytes);
        buffer.put((byte) 0);
        buffer.put((byte) 0); // End of message

        socket.getOutputStream().write(buffer.array());
        socket.getOutputStream().flush();
    }

    // ==============================================================================
    // UTILITY METHODS
    // ==============================================================================

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (Math.random() * 256);
        }
        return bytes;
    }

    private void recordDatabaseAttack(String sourceIP, String target, String payload, String details) {
        AttackEvent event = new AttackEvent();
        event.setAttackType(AttackType.DATABASE_PROBE);
        event.setSourceIp(sourceIP);
        event.setTargetEndpoint(target);
        event.setPayload(payload);
        event.setSeverity(Severity.HIGH);
        event.setGeolocation(geoLocationService.getLocation(sourceIP));
        event.setAttackDetails(details);

        attackEventRepository.save(event);

        attackDetectionService.recordAttack(event);
    }

    // ==============================================================================
    // SERVICE MANAGEMENT
    // ==============================================================================

    public void stopDatabaseHoneypots() {
        log.info("Stopping Database Honeypot Services...");

        mysqlRunning = false;
        postgresRunning = false;

        try {
            if (mysqlSocket != null && !mysqlSocket.isClosed()) {
                mysqlSocket.close();
                log.info("MySQL Honeypot stopped");
            }
        } catch (IOException e) {
            log.error("Error stopping MySQL Honeypot: ", e);
        }

        try {
            if (postgresSocket != null && !postgresSocket.isClosed()) {
                postgresSocket.close();
                log.info("PostgreSQL Honeypot stopped");
            }
        } catch (IOException e) {
            log.error("Error stopping PostgreSQL Honeypot: ", e);
        }

        mysqlExecutor.shutdown();
        postgresExecutor.shutdown();
    }

    public boolean isMySQLRunning() {
        return mysqlRunning;
    }

    public boolean isPostgreSQLRunning() {
        return postgresRunning;
    }

    public int getMySQLConnections() {
        return mysqlConnections.get();
    }

    public int getPostgreSQLConnections() {
        return postgresConnections.get();
    }

    // ==============================================================================
    // INNER CLASSES
    // ==============================================================================

    private static class MySQLAuthInfo {
        final String username;
        final String database;
        final boolean hasPassword;
        final int clientFlags;

        MySQLAuthInfo(String username, String database, boolean hasPassword, int clientFlags) {
            this.username = username;
            this.database = database;
            this.hasPassword = hasPassword;
            this.clientFlags = clientFlags;
        }
    }

    private static class PostgreSQLStartupInfo {
        final String user;
        final String database;
        final int protocolVersion;

        PostgreSQLStartupInfo(String user, String database, int protocolVersion) {
            this.user = user;
            this.database = database;
            this.protocolVersion = protocolVersion;
        }
    }

    private static class DatabaseThreadFactory implements ThreadFactory {
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String prefix;

        DatabaseThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r, prefix + "-Honeypot-" + threadNumber.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        }
    }
}
