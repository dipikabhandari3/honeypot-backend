package com.example.honeypotmanagement.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
@RequiredArgsConstructor
public class GeoLocationService {

    private final RestTemplate restTemplate;

    private final Map<String, String> ipLocationCache = new ConcurrentHashMap<>();

    // Free IP geolocation service
    private static final String GEOLOCATION_API = "http://ip-api.com/json/";

    public String getLocation(String ipAddress) {
        // Skip localhost and private IPs
        if (isLocalOrPrivateIP(ipAddress)) {
            return "Local/Private Network";
        }

        // Check cache first
        if (ipLocationCache.containsKey(ipAddress)) {
            return ipLocationCache.get(ipAddress);
        }

        try {
            String url = GEOLOCATION_API + ipAddress + "?fields=status,country,regionName,city,lat,lon,isp";
            Map<String, Object> response = restTemplate.getForObject(url, Map.class);

            if (response != null && "success".equals(response.get("status"))) {
                String location = String.format("%s, %s, %s (ISP: %s)",
                        response.get("city"),
                        response.get("regionName"),
                        response.get("country"),
                        response.get("isp"));

                // Cache the result
                ipLocationCache.put(ipAddress, location);
                return location;
            }
        } catch (Exception e) {
            log.warn("Failed to get location for IP {}: {}", ipAddress, e.getMessage());
        }

        // Fallback to IP only
        String fallback = "Unknown Location (" + ipAddress + ")";
        ipLocationCache.put(ipAddress, fallback);
        return fallback;
    }

    public Map<String, Object> getDetailedLocation(String ipAddress) {
        Map<String, Object> result = new HashMap<>();

        if (isLocalOrPrivateIP(ipAddress)) {
            result.put("country", "Local");
            result.put("city", "localhost");
            result.put("latitude", 0.0);
            result.put("longitude", 0.0);
            result.put("isp", "Local Network");
            return result;
        }

        try {
            String url = GEOLOCATION_API + ipAddress + "?fields=status,country,regionName,city,lat,lon,isp,timezone";
            Map<String, Object> response = restTemplate.getForObject(url, Map.class);

            if (response != null && "success".equals(response.get("status"))) {
                result.put("country", response.get("country"));
                result.put("region", response.get("regionName"));
                result.put("city", response.get("city"));
                result.put("latitude", response.get("lat"));
                result.put("longitude", response.get("lon"));
                result.put("isp", response.get("isp"));
                result.put("timezone", response.get("timezone"));
                result.put("ipAddress", ipAddress);
                return result;
            }
        } catch (Exception e) {
            log.warn("Failed to get detailed location for IP {}: {}", ipAddress, e.getMessage());
        }

        // Fallback
        result.put("country", "Unknown");
        result.put("city", "Unknown");
        result.put("latitude", 0.0);
        result.put("longitude", 0.0);
        result.put("isp", "Unknown");
        result.put("ipAddress", ipAddress);
        return result;
    }

    private boolean isLocalOrPrivateIP(String ipAddress) {
        if (ipAddress == null) return true;

        return ipAddress.equals("127.0.0.1") ||
                ipAddress.equals("localhost") ||
                ipAddress.equals("0:0:0:0:0:0:0:1") ||
                ipAddress.equals("::1") ||
                ipAddress.startsWith("192.168.") ||
                ipAddress.startsWith("10.") ||
                ipAddress.startsWith("172.16.") ||
                ipAddress.startsWith("172.17.") ||
                ipAddress.startsWith("172.18.") ||
                ipAddress.startsWith("172.19.") ||
                ipAddress.startsWith("172.2") ||
                ipAddress.startsWith("172.30.") ||
                ipAddress.startsWith("172.31.");
    }

    public void clearCache() {
        ipLocationCache.clear();
        log.info("IP location cache cleared");
    }
}
