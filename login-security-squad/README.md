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
