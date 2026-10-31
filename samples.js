/**
 * PhishGuard AI — Realistic Threat and Clean Sample Corpus
 * Provides instant test cases for users to explore threat detection vectors.
 */

(function (global) {
  'use strict';

  const SAMPLES = {
    paypal: {
      id: 'paypal',
      name: '⚠️ PayPal Suspension Phish',
      raw: `From: "PayPal Security Center" <service-update@paypa1-security-verification.xyz>
Reply-To: refund-helpdesk99@gmail.com
Return-Path: <bounce@unverified-relay.top>
Subject: URGENT: Your PayPal account has been restricted!
Date: Thu, 31 Oct 2026 14:15:30 +0000
Authentication-Results: mx.google.com; dkim=fail; spf=softfail

Dear Valued Customer,

We detected unauthorized sign-in attempts to your PayPal account from an unrecognized IP address in Moscow, Russia.

For your protection, your account privileges have been restricted. Failure to verify your identity within 24 hours will result in permanent account termination and forfeiture of remaining balances.

Please click the secure link below to confirm your password and billing details:
<a href="http://185.220.101.5/paypal-login/auth.php">https://www.paypal.com/signin/security-verify</a>

If you did not make this request, our security team is standing by.

Sincerely,
PayPal Identity Protection Team
Copyright © 1999-2026 PayPal Inc. All rights reserved.`
    },

    ceo_bec: {
      id: 'ceo_bec',
      name: '👔 CEO Wire Fraud (BEC)',
      raw: `From: "Jonathan Vance - Chief Executive Officer" <ceo.jvance@corporate-management.com>
Reply-To: executive.jvance@consultant-private.ru
Subject: STRICTLY CONFIDENTIAL - Wire Transfer Authorization Request
Date: Fri, 01 Nov 2026 09:30:12 -0400

Are you at your desk right now?

I am currently in an urgent board meeting and cannot take phone calls. We have closed an unexpected vendor acquisition that requires an immediate confidential wire transfer of $48,500 today before 3:00 PM EST.

Please confirm you can handle this wire transfer immediately so I can forward the bank wiring coordinates. Keep this strictly private between us until the official press release on Monday.

Do not call me as my phone is turned off during the executive conference.

Best regards,

Jonathan Vance
Chief Executive Officer
Acme Global Logistics Inc.`
    },

    geeksquad: {
      id: 'geeksquad',
      name: '🧾 Geek Squad / Norton Fake Invoice',
      raw: `From: "Geek Squad Total Tech Support" <billing-receipt-notification@mail-services-online.link>
Reply-To: noreply-refund@mail-services-online.link
Subject: Invoice #GS-8829104: Auto-renewal completed for $499.99
Date: Wed, 30 Oct 2026 11:22:00 +0000

INVOICE & RENEWAL RECEIPT

Dear Customer,

Thank you for your continued loyalty with Geek Squad & BestBuy Total Tech 360 Security!

Your annual subscription has been auto-renewed for another 3 years. The total amount of $499.99 has been deducted from your registered checking account.

Item Description: Geek Squad Total Security 3-Year Extended Protection
Order Number: GS-8829104-B
Amount Deducted: $499.99 USD
Payment Status: Completed

If you did not authorize this charge or wish to cancel your subscription and claim a full refund, please call our toll-free customer support line immediately:

Toll-Free Support Line: +1 (888) 492-3819

Please do not reply to this automated email. All refund cancellations must be processed over the telephone with a billing technician within 24 hours.`
    },

    dhl_malware: {
      id: 'dhl_malware',
      name: '📦 DHL Shipment & Malware Dropper',
      raw: `From: "DHL Express Delivery Tracking" <support@dhl-parcel-delivery.work>
Subject: Exception Notice: Your package #DHL-99214-US could not be delivered
Date: Mon, 28 Oct 2026 08:45:10 +0100

Dear Customer,

Your parcel with tracking code #DHL-99214-US arrived at the local distribution hub, but delivery could not be completed due to an incorrect shipping address and an unpaid customs clearance fee of $3.50.

Immediate action required: The package will be returned to the international sender if fees are not settled within 48 hours.

Please download the attached delivery receipt to confirm your address and schedule re-delivery:
Attachment: DHL_Express_Shipping_Label_99214.pdf.exe

Or track online:
<a href="http://194.87.139.77/dhl/update">https://www.dhl.com/en/express/tracking.html</a>

Thank you for shipping with DHL Express.`
    },

    m365_phish: {
      id: 'm365_phish',
      name: '🔑 M365 Password Expiration Phish',
      raw: `From: "Microsoft 365 Cloud Security" <no-reply@micros0ft-account-notification.top>
Subject: FINAL NOTICE: Your Microsoft 365 password expires today!
Date: Thu, 31 Oct 2026 16:50:00 +0000

Microsoft Office 365 Security Notice

Dear User,

Your organization's Microsoft 365 enterprise account password will expire in 2 hours.

To keep your current password and prevent disruption to your email, Teams, and OneDrive storage, you must validate your credentials immediately.

<a href="https://bit.ly/3m365-verify-login">Click here to retain your current password</a>

If you fail to verify before the deadline, your account will be locked and all active sessions will be terminated by your system administrator.

Microsoft Cloud Identity Services
One Microsoft Way, Redmond, WA`
    },

    github_safe: {
      id: 'github_safe',
      name: '✅ Safe GitHub Security Alert',
      raw: `From: "GitHub" <notifications@github.com>
To: developer@example.com
Subject: [GitHub] A personal access token has been generated
Date: Fri, 01 Nov 2026 03:15:00 +0000
Authentication-Results: mx.google.com; dkim=pass header.i=@github.com; spf=pass smtp.mailfrom=notifications@github.com; dmarc=pass

Hey developer,

A new personal access token (classic) was added to your account on GitHub.

Token name: Antigravity Deployment
Account: developer
Created: Nov 1, 2026 03:15 UTC

If you generated this token, you can safely disregard this email.

If you did not generate this token, please visit your security settings to revoke it immediately:
https://github.com/settings/tokens

To learn more about keeping your account safe, read our documentation on best security practices:
https://docs.github.com/articles/keeping-your-account-and-data-secure

Thanks,
The GitHub Team`
    }
  };

  global.PhishGuardSamples = SAMPLES;

})(typeof window !== 'undefined' ? window : globalThis);
