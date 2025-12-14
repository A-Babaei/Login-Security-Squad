# Login Security Squad

**Contributors:** Jules
**Requires at least:** 5.0
**Tested up to:** 6.5
**Stable tag:** 1.3
**License:** GPL v2 or later
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html

A comprehensive security plugin for WordPress that detects and prevents users from sharing login credentials, protecting your site from unauthorized access.

## Description

Login Security Squad is a powerful security solution designed to protect your WordPress site by monitoring user activity for signs of account sharing. It uses a combination of session management, IP and device fingerprinting, and behavioral analysis to identify suspicious behavior and block unauthorized access. With a full suite of admin tools, you can configure the plugin to meet your specific security needs and keep a close eye on user activity.

### Key Features

*   **Concurrent Session Limiting:** Prevent multiple users from logging into the same account simultaneously.
*   **IP & Device Fingerprinting:** Flag suspicious activity by monitoring logins from multiple IPs or devices.
*   **OTP Verification:** Secure user accounts by requiring a one-time password for suspicious logins.
*   **Content Access Monitoring:** Get alerted to suspicious activity by tracking access to your protected content.
*   **Admin Dashboard & Controls:** A full suite of tools for monitoring and managing user activity.

## Installation

1.  Download the `login-security-squad.zip` file.
2.  In your WordPress admin panel, go to **Plugins** > **Add New**.
3.  Click **Upload Plugin** and select the downloaded zip file.
4.  Activate the plugin.
5.  Go to **Login Security > Anti-Sharing** to configure the plugin.

## Frequently Asked Questions (FAQ)

**Q: Can I exempt certain user roles from being blocked?**

A: Yes, by default, users with the `administrator` or `teacher` roles are exempt from all suspicious activity blocking.

**Q: What happens when a user is blocked?**

A: When a user is blocked, their password is changed, and they are immediately logged out. To regain access, they will need to use the "Forgot Password" feature to reset their password.

**Q: Can I manually block or unblock a user?**

A: Yes, you can manually block or unblock any user from the **Login Security > Manual Blocking / Unblocking** section in the admin dashboard.

**Q: How does the plugin handle sensitive data?**

A: All sensitive user data, such as IP addresses and device fingerprints, is encrypted in the database to ensure it remains secure.

## Support

If you need help with the plugin or have any questions, please open an issue on our [GitHub repository](https://example.com/support).

## Changelog

### 1.3 (2024-07-15)
*   Fixed a bug that was preventing the plugin from being installed correctly.
*   Updated the plugin version to 1.3.

### 1.2 (2024-07-15)
*   Exempted admins and teachers from suspicious activity blocking.
*   Improved the manual blocking UI to allow for both blocking and unblocking of users.
*   Enhanced the admin UI by displaying usernames in the login logs.
*   Fixed a bug that prevented admins from unblocking users who were locked out due to too many failed OTP attempts.
*   Fixed a fatal error on activation caused by a syntax error.
*   Added concurrent session limiting.
*   Added IP and device fingerprinting.
*   Added OTP verification for suspicious logins.
*   Added usage pattern monitoring.
*   Added a dashboard widget for flagged accounts.
*   Added "Warn," "Suspend," and "Ban" actions to the users list.
*   Added a meta box to protect content.
*   Added a toggle for geolocation flagging.
*   Encrypted sensitive data in the database.
*   Patched a critical security vulnerability where a banned user could log in using their email address.

## Enable Anti-Sharing Features (Checkbox, default: unchecked)

Purpose: Activates the core suite of protections against video sharing, including disabling right-click/context menu on the player, preventing screenshot/screen recording detection (via JS event listeners), and enforcing watermark overlays on videos.
Code Implementation: When enabled (if (get_option('enable_anti_sharing') === '1')), it hooks into the shortcode renderer (add_shortcode('secure_video_player')) to inject CSS/JS that blocks dev tools inspection and adds dynamic watermarks based on user IP. It also enables logging of playback events to a custom DB table (wp_secure_video_logs).
Effect: Videos become harder to download or share directly. Recommended: Enable for sensitive content.

* 2. Enable Geolocation Flagging (Checkbox, default: unchecked)

Purpose: Uses the browser's Geolocation API to track viewer locations and flag access from unexpected regions (e.g., outside your target audience's country).
Code Implementation: On player load, JS (player-security.js) calls navigator.geolocation.getCurrentPosition() and sends coords to a PHP endpoint (/wp-admin/admin-ajax.php?action=flag_geolocation). Server-side, it compares against stored user locations (from first access) using a simple Haversine distance formula. If beyond the distance threshold, it logs a flag and may pause playback.
Effect: Helps detect VPN/proxy use or unauthorized geographic sharing. Integrates with admin notifications. Recommended: Enable if your content is region-locked.

* 3. Enable OTP Verification (Checkbox, default: unchecked)

Purpose: Requires users to enter a one-time password (sent via email/SMS) before accessing protected videos, adding a layer of authentication beyond logins.
Code Implementation: Triggered on first play (if (get_option('enable_otp') === '1' && !session_otp_verified())), it generates a 6-digit code using rand(100000, 999999), emails it via wp_mail(), and verifies on submission via AJAX (action=verify_otp). Nonces are used for security (wp_create_nonce('otp_verify')). Failed attempts increment a counter and lockout after 3 tries.
Effect: Prevents casual sharing by requiring email verification per session. Note: Requires an SMTP plugin for reliable delivery. Recommended: Enable for high-value videos.

* 4. IP Threshold (Number input, default: 5)

Purpose: Sets the maximum number of unique IP addresses allowed per user/device within a session or grace period before flagging as suspicious (e.g., potential multi-device sharing).
Code Implementation: In the session handler (start_secure_session()), it tracks IPs in $_SESSION['user_ips'] array. If count($ips) > get_option('ip_threshold'), it triggers a flag, possibly requiring re-verification. Stored in transients for performance (set_transient('ip_check_' . $user_id, $ips)).
Effect: Catches users switching networks/VPNs to share links. Recommended: 3-5 for strict control; higher for mobile users.

* 5. Distance Threshold (km) (Number input, default: 100)

Purpose: Defines the maximum allowed change in geolocation distance between video accesses for the same user (e.g., flags if someone "moves" too far, indicating sharing).
Code Implementation: Uses the Haversine function (haversine_distance($lat1, $lon1, $lat2, $lon2)) in the geolocation AJAX handler. Compares current coords to stored baseline (update_option('user_location_' . $user_id, $coords)). If distance > threshold, logs to admin and may block.
Effect: Detects cross-country sharing. Only active if geolocation flagging is enabled. Recommended: 50-200 km, depending on your audience mobility.

* 6. Admin Notification Email (Text input, default: empty)

A.Babaei, [12/14/2025 4:42 PM]
Purpose: Specifies the email address where alerts for flagged activities (e.g., threshold breaches, suspicious logins) are sent.
Code Implementation: Pulled via get_option('admin_notification_email') in logging functions. When a flag occurs (e.g., log_suspicious_activity($event)), it calls wp_mail($email, 'Security Alert: Video Access Flagged', $message).
Effect: Keeps site admins informed in real-time. Recommended: Use a dedicated monitoring email like the one shown (S.jalili@yahoo.com).

* 7. Session Limit (Checkbox + Number input, default: unchecked, limit 1)

Purpose: Limits the number of concurrent or sequential sessions per user to prevent multiple logins/shares.
Code Implementation: If enabled, checks session_count in transients (get_transient('session_count_' . $user_id)). Increments on start (session_start() hook) and destroys old ones if over limit. Ties into device fingerprint for accuracy.
Effect: Stops simultaneous viewing on multiple devices. Recommended: Enable with limit 1-2.

* 8. Device Fingerprint Threshold (Number input, default: 3)

Purpose: Monitors unique device fingerprints (browser/user-agent hash) and flags if too many are detected per user, indicating sharing across devices.
Code Implementation: Generates fingerprint via JS (fingerprintjs library enqueued) and hashes it (md5($user_agent . $screen_res . $timezone)). Stores in session/DB; if count($fingerprints) > threshold, flags via add_flag('device_mismatch').
Effect: Detects emulator or multi-device abuse. Recommended: 2-4 for most users.

* 9. Content Access Threshold (Number input, default: 10)

Purpose: Maximum number of video views/plays allowed per user/session before requiring re-authentication or flagging.
Code Implementation: Tracks plays in wp_secure_video_logs table ($wpdb->insert(..., ['action' => 'play', 'video_id' => $id])). Queries count (SELECT COUNT(*) ... WHERE user_id = $user_id AND date > NOW() - INTERVAL 1 DAY); if exceeded, prompts OTP or blocks.
Effect: Limits binge-watching or automated scraping. Recommended: 5-20, based on content length.

* 10. IP Grace Period (days) (Number/Select input, default: 7)

Purpose: Number of days to "forgive" IP changes (e.g., travel) before strict threshold enforcement kicks in.
Code Implementation: Uses date('Y-m-d', strtotime('-' . $days . ' days')) to filter logs in threshold checks. Resets baseline IP/location after period.
Effect: Balances security with legitimate use (e.g., vacations). Recommended: 7-30 days.

write and Design by: A.Babaei, [12/14/2025 4:42 PM]

