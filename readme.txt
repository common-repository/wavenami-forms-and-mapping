=== Wavenami Ticketing, Symposium Management, Application Forms & Mapping ===
Contributors: wavenami
Plugin Name: Wavenami Ticketing, Symposiums, Application Forms & Mapping
Plugin URI: https://www.wavenami.com/wordpress-form-plugin/
Tags: ticketing, abstract management, digital hub, booth mapping, event registration, sponsorship, speaker management, crm, analytics
Author: Wavenami
Requires at least: 6.0
Tested up to: 6.4
Requires PHP: 7.4
Version: 1.0.11
Stable tag: 1.0.11
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Wavenami is a unified solution built for Administrators, Organizers and Producers to manage all aspects of the complete event life cycle.

== Description ==

Wavenami is used to help Administrators, Organizers and Producers turn out multi-faceted events within one integrated, GDPR and CCPA compliant system.

This Wavenami plugin allows you to easily embed dynamic application forms & booth mapping directly into your website. All applicant forms are managed from the Wavenami Administrator dashboard. Dynamic booth mapping allows for applicants to reserve their booth from the map and be taken directly to the registration form.

* **Dynamic Forms:** Applicant types range from sponsors, attendees, speakers, volunteers or exhibitors who can select booth locations, purchase assets, amenities and upgrades, upload documents and media files, provide e-signatures and pay for cart items. Applicant form review on Administrator dashboard. Built in support for Stripe & Paypal payment gateways.

* **Advanced Mapping:** Plot interactive booths with different sizes and pricing levels. Advanced features include dynamic pricing and group area restrictions by applicant type (ie. Exhibitors vs Sponsors).

* **Forward Facing Maps:** Forward facing maps have two uses. **1)** Display the interactive booth map and Exhibitors or Sponsor locations with details for each. **2)** Exhibitors or Sponsors can start the application process by selecting an available booth.

* **Speaker Abstract Management:** Capture speaker submissions and review on Administrator dashboard. Choose speaker roster in Session and Agenda Track Builder.

* **Session and Agenda Track Builder.** Features "chained" speaker track builder which allows Administrators to set up to 4 levels of track topics for optimization. This works in conjunction with Wavenami's session and agenda builder systems.

* **Mobile Ticketing/Scanning:** Free Mobile Ticketing/Check-in App allows for easy point of entry control of to your events and symposiums.

== Wavenami Granular Controls ==

* Complete exhibitor/speaker/attendee registration management, from start to finish
* Full GDPR/California privacy policy compliance
* WP Multisite aware for Network Activation
* Native iframes shortcode for form & map embedding
* Booth grouping/restrictions by Applicant type (ie. Sponsors)
* Session/Conference speaker forms to feed Sessions Builder
* Ticketing sales with support for badging & barcodes
* Custom badge designer with barcode/image support
* Mobile Ticketing Check-in App (Android/iOS)
* Manage and review your applicants easily and efficiently
* Block application deposit until approved
* Integrates with Chatra & Hubspot chat widgets in registration forms
* Block balance payment until approved
* Flexible discount codes
* Form chat allows you to field questions directly from your application forms via Chatra.
* Payment support via Stripe directly to your account
* Auto-calculate and add credit card processor fees into base prices
* Split payments of application fees based on percentage ratios and due dates
* Responsive, mobile friendly forms with great UX
* Import your current vendor list via XLS file, including custom fields
* Venue location mapping, selection & pricing (ie. booth spaces)
* Map reservations & placement by organizer with price override/expiration date
* "Earlybird" fee discounts with auto-expiration date
* Amenity discount options, both global and form specific tied to early bird discounts
* Dynamic contract generation with e-signatures
* Supports multiple forms feeding a single event for greater flexibility
* Applicants can go back to application, make changes & payments at any time
* Customizable profile fields and sort order
* Application deposit payment support that are subtracted from remaining payments
* Applicant/vendor profiles and custom keywords
* Dynamic document requirements and uploads based on applicant/vendor type
* Streamlined document auditing
* Amenity selection and pricing (ie. tables, tents)
* email and SMS text blasts to individual and groups of vendors
* Form validation
* Easy sorting of form fields and form values (selectors)
* Granular "required" field settings along with asterisk (*) after field label
* and more...

== Installation ==

You need a <a href="https://www.wavenami.com" target="_blank">Wavenami</a> account to use this plugin.

After you create your application forms and booth maps from Wavenami, use the corresponding shortcodes in Wordpress to display your forms and maps. Shortcodes for each can be found from **[Wordpress > Settings > Wavenami]**.

= Adding your API Key =

1. Generate your API key from **[Wavenami.com > Settings > Wordpress API]**
1. From **[Wordpress > Settings > Wavenami**] paste your API key into the "Private API Key" field and save.
1. **NOTE:** After you add your API key, you will see your form & map shortcodes in the corresponding tabs.

= Automatic Installation =

1. Go to **[Wordpress > Plugins > Add New]** in your WordPress dashboard.
1. Search `wavenami` to find this plugin, by Vandenberg Media Inc.
1. Click **Install Now** to install it and then activate it after the installation.
1. **NOTE**: [Wordpress > Settings > Permalinks] must be set to anything OTHER THAN "Plain/Default". This is usually the case already. Also see: <a href="https://wordpress.org/support/article/settings-permalinks-screen/" target="_blank">Permalinks</a>

= Manual Installation =

1. Download the plugin from <a href="http://www.wavenami.com">Wavenami.com</a> and follow the instructions on the page.

== 3rd Party service integrations ==

This plug-in allows you to enable a "form-chat" feature and allows you to have a text conversation with those who are filling out a form. This function is DISABLED by default and will only appear if you enable it under [Wavenami > Forms > Settings > Form Chat].

**Supported Services**
Chatra.io <a href="https://chatra.io/" target="_blank">https://chatra.io/</a>
Also see Chatra <a href="https://chatra.io/terms-of-service/" target="_blank">terms of service</a> & <a href="https://chatra.io/privacy-policy/" target="_blank">privacy policy</a>

Hubspot Chat <a href="https://www.hubspot.com/" target="_blank">https://hubspot.com/</a>
If using Hubspot integration, your chat configuration will be pulled in from **js.hs-scripts.com** to ensure that new HubSpot features like messages or pop-up forms are automatically added to your form.
See <a href="https://knowledge.hubspot.com/reports/what-is-the-hs-scripts-embed-code-loading-on-my-website" target="_blank">what-is-the-hs-scripts</a> for more information.
Also see Hubspot <a href="https://legal.hubspot.com/terms-of-service" target="_blank">terms of service</a> & <a href="https://legal.hubspot.com/privacy-policy" target="_blank">privacy policy</a>

== Frequently Asked Questions ==

= What exactly does this plugin do? =

It displays your event & speaker registration forms and maps. You first need to register on Wavenami and create your first event. Once you do so and add your API key, the plugin will display your registration form via shortcode. All form details are generated and saved to your <a href="http://www.wavenami.com">Wavenami.com</a> account.

For more faqs, please see our <a href="https://www.wavenami.com/faq/">FAQ page</a>.

= What payment gateways do you support? =

We support Stripe & Paypal. All you need to do is authorize Wavenami to accept payments on your behalf. We recommend Stripe because of the excellent reporting and management Stripe offers.

= What does it cost? =

The plugin is free to use. Wavenami.com is free to try for your event registration and mapping. You can setup everything and test with up to 5 applicants without paying a dime. See Wavenami.com for details on service pricing.

== Screenshots ==

1. Get your private API key from Wavenami.com
2. Add your API key to the Wavenami API Settings.
3. Access your event form shortcodes on the Shortcode tab.
4. Insert your shortcode into a blank Page (not a Post) and select the Wavenami template for display.
5. Your vendor registration form will be displayed on your page.
6. Forms are mobile friendly for tablets and smartphones.
7. Document uploads are handled automatically based on vendor type.
8. Applicants can select the venue location or booth they want.
9. Vendor amenities are selectable, including venue setup location.
10. Event terms are displayed for them to sign off on.
11. e-Signatures can be made from desktops, tables or phones.
12. Payments can be made based on your payment preferences.

== Changelog ==

= 1.0.11 =
* NEW: map-to-map navigation via dropdown
* Fix: width CSS of main map area

= 1.0.10 =
* Auto-recall contact fields on cart page
* Added logo in exhibitor detail popup
* Map exhibitor detail popup right justified with scrolling body content
* Fix: Scroll issue on map vendor listing
* Fix: CC filter for Amex

= 1.0.9 =
* Badge mods for catching duplicate badge email profiles
* Check for vars before usage

= 1.0.8 =
* NEW: setting to limit or disable keyword selections

= 1.0.7 =
* Fixed display of custom cart page header text
* CSS mods for text block well shading
* Fix T&C text block to read-only

= 1.0.6 =
* Added UI tweaks for better button spacing

= 1.0.5 =
* Correct json warning with mapping.
* Correct issues with last WP update and plugin.

= 1.0.4 =
* Added custom fields for social links
* Added new processor support

= 1.0.3 =
* Restore rich formatting for T&C display

= 1.0.2 =
* Fixed data call to plugin path

= 1.0.1 =
* Fixed call to missing class

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.0.11 =
* NEW: map-to-map navigation via dropdown
* Fix: width CSS of main map area
