package com.example.honeypotmanagement.service;

import com.example.honeypotmanagement.enums.AttackType;
import com.example.honeypotmanagement.enums.Severity;
import com.example.honeypotmanagement.model.AttackEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SSHHoneypotService {

    private final AttackDetectionService attackDetectionService;
    private final GeoLocationService geoLocationService;
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private ServerSocket serverSocket;

    @EventListener(ApplicationReadyEvent.class)
    public void startSSHHoneypot() {
        executorService.submit(this::runSSHHoneypot);
    }

    private void runSSHHoneypot() {
        try {
            serverSocket = new ServerSocket(2222);
            log.info("🔐 SSH Honeypot started on port 2222");

            while (!serverSocket.isClosed()) {
                Socket clientSocket = serverSocket.accept();
                executorService.submit(() -> handleSSHConnection(clientSocket));
            }
        } catch (IOException e) {
            if (!serverSocket.isClosed()) {
                log.error("SSH Honeypot error: ", e);
            }
        }
    }

    private void handleSSHConnection(Socket clientSocket) {
        String clientIP = clientSocket.getInetAddress().getHostAddress();
        log.info("SSH connection attempt from: {}", clientIP);

        try {
            // Send fake SSH banner
            String sshBanner = "SSH-2.0-OpenSSH_8.9\r\n";
            clientSocket.getOutputStream().write(sshBanner.getBytes(StandardCharsets.UTF_8));

            // Read client data
            byte[] buffer = new byte[1024];
            int bytesRead = clientSocket.getInputStream().read(buffer);

            if (bytesRead > 0) {
                String clientData = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
                log.info("SSH client data from {}: {}", clientIP, clientData.trim());

                // Record the SSH connection attempt
                recordSSHAttack(clientIP, clientData, "SSH connection attempt");

                // Simulate authentication process
                simulateSSHAuthentication(clientSocket, clientIP);
            }

        } catch (IOException e) {
            log.debug("SSH client disconnected: {}", clientIP);
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                log.debug("Error closing SSH client socket: ", e);
            }
        }
    }

    private void simulateSSHAuthentication(Socket clientSocket, String clientIP) throws IOException {
        // Send authentication request
        String authRequest = "Please enter username: ";
        clientSocket.getOutputStream().write(authRequest.getBytes(StandardCharsets.UTF_8));

        // Read username attempt
        byte[] buffer = new byte[256];
        int bytesRead = clientSocket.getInputStream().read(buffer);

        if (bytesRead > 0) {
            String username = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).trim();
            log.info("SSH username attempt from {}: {}", clientIP, username);

            // Record brute force attempt
            recordSSHAttack(clientIP, username, "SSH username: " + username);

            // Send password request
            String passwordRequest = "Password: ";
            clientSocket.getOutputStream().write(passwordRequest.getBytes(StandardCharsets.UTF_8));

            // Read password attempt
            bytesRead = clientSocket.getInputStream().read(buffer);
            if (bytesRead > 0) {
                String password = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8).trim();
                log.info("SSH password attempt from {} for user {}: {}", clientIP, username, password);

                // Record the login attempt
                recordSSHAttack(clientIP, username + ":" + password,
                        "SSH login attempt - User: " + username + ", Pass: " + password);

                // Always deny access but keep them engaged
                String denial = "Access denied.\r\n";
                clientSocket.getOutputStream().write(denial.getBytes(StandardCharsets.UTF_8));

                // Simulate some delay to make it realistic
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private void recordSSHAttack(String sourceIP, String payload, String details) {
        AttackEvent event = new AttackEvent();
        event.setAttackType(AttackType.SSH_BRUTE_FORCE);
        event.setSourceIp(sourceIP);
        event.setTargetEndpoint("SSH:2222");
        event.setPayload(payload);
        event.setSeverity(Severity.HIGH);
        event.setGeolocation(geoLocationService.getLocation(sourceIP));
        event.setAttackDetails(details);

        attackDetectionService.recordAttack(event);
    }

    public void stopSSHHoneypot() {
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                log.info("SSH Honeypot stopped");
            }
        } catch (IOException e) {
            log.error("Error stopping SSH Honeypot: ", e);
        }
    }
}
