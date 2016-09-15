# open-xchange-cas
CAS SSO Plugin for Open-Xchange as an OSGi Bundle with ClearPass support, so that credentials will be stored for mail server access.

Configuration file: /src/main/resources/conf/cas-sso.properties

Installation:

1. Import project into Maven-enabled Eclipse
2. Add Open-XChange and JSON Libraries to build path (com.openexchange.configread, com.openexchange.documentation, com.openexchange.global, com.openexchange.java, com.openexchange.osgi, com.openexchange.server)
3. Export a library jar called "openxchange-cas-sso.jar" (due to OSGi Classpath)
4. Place jar in OX folder "bundles/de.hofuniversity.iisys.ox.sso/"
5. Edit cas-sso.properties to match your setup
6. Place contents of /src/main/resources/ in "bundles/de.hofuniversity.iisys.ox.sso/"
7. Place cas-sso.properties in etc/ (in OX directory)
8. echo "/opt/open-xchange/bundles/de.hofuniversity.iisys.ox.sso@start" > osgi/bundle.d/de.hofuniversity.iisys.ox.sso.ini
9. Restart Open-XChange
