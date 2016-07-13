# Marker to tell the VCL compiler that this VCL has been adapted to the
# new 4.0 format.
vcl 4.0;

# Standard module
# See https://www.varnish-cache.org/docs/4.0/reference/vmod_std.generated.html
import std;

# Default backend definition. Set this to point to your content server.
backend default {
    .host = "10.5.101.31";
    .port = "80";
    .connect_timeout = 3600s;
    .first_byte_timeout = 3600s;
    .between_bytes_timeout = 3600s;
}

# Backend for the piwik container.
backend stats {
    .host = "127.0.0.1";
    .port = "8093";
    .connect_timeout = 3600s;
    .first_byte_timeout = 3600s;
    .between_bytes_timeout = 3600s;
}

# See https://www.varnish-cache.org/docs/4.0/reference/vcl.html#access-control-list-acl
acl purge_ban {
  # Simple access control list for allowing item purge for the self machine
  "127.0.0.1"/32; // We can use '"localhost";' instead
}
acl allowed_monitors {
  # Simple access control list for allowing item purge for the self machine
  "127.0.0.1"/32; // We can use'"localhost";' instead
}
acl own_proxys {
  "10.5.68.1"/32;
  "10.5.68.2"/32;
}

# vcl_recv: Called at the beginning of a request, after the complete request
# has been received and parsed. Its purpose is to decide whether or not to
# serve the request, how to do it, and, if applicable, which backend to use.
# See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-built-in-subs.html#vcl-recv
sub vcl_recv {

  # Custom response implementation example in order to check that Varnish is
  # working properly.
  # This is usefull for automatic monitoring with monit or when Varnish is
  # behind another proxies like HAProxy.
  if ( ( req.http.host == "monitor.server.health"
      || req.http.host == "health.varnish" )
    && client.ip ~ allowed_monitors
    && ( req.method == "OPTIONS" || req.method == "GET" )
  ) {
    return (synth(200, "OK"));
  }
  # Purge logic
  # See https://www.varnish-cache.org/docs/4.0/users-guide/purging.html#http-purging
  # SeeV3 https://www.varnish-software.com/static/book/Cache_invalidation.html#removing-a-single-object
  if ( req.method == "PURGE" ) {
    if ( client.ip !~ purge_ban ) {
      return (synth(405, "Not allowed."));
    }
    return (purge);
  }
  # Ban logic
  # See https://www.varnish-cache.org/docs/4.0/users-guide/purging.html#bans
  if ( req.method == "BAN" ) {
    if ( client.ip !~ purge_ban ) {
      return (synth(405, "Not allowed."));
    }
    ban( "req.http.host == " + req.http.host +
      "&& req.url == " + req.url);
    return (synth(200, "Ban added"));
  }

  if ( req.method == "PRI" ) {
    # We do not support SPDY or HTTP/2.0
    return (synth(405));
  }
  if ( req.method != "GET"
    && req.method != "HEAD"
    && req.method != "PUT"
    && req.method != "POST"
    && req.method != "TRACE"
    && req.method != "OPTIONS"
    && req.method != "DELETE"
  ) {
    # Non-RFC2616 or CONNECT which is weird.
    return (pipe);
  }

  # Send the stats requests to the piwik container.
  if (req.http.host ~ "stats\.humanitarianresponse\.info" && req.backend_hint == default) {
  	set req.backend_hint = stats;
  }

  # Handle redirections.
  call perm_redirections_recv;

  # See https://www.varnish-cache.org/docs/4.0/whats-new/upgrading.html#x-forwarded-for-is-now-set-before-vcl-recv
  if ( req.restarts == 0 && client.ip ~ own_proxys && req.http.x-forwarded-for) {
    set req.http.X-Forwarded-For = regsub(req.http.X-Forwarded-For, "(, )?(10\.5\.68\.1|10\.5\.68\.2)", "");
  }

  if ( req.method != "GET"
    && req.method != "HEAD"
  ) {
    return (pass);
  }
  if ( req.http.Authorization ) {
    return (pass);
  }
  # Websocket support
  # See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-example-websockets.html
  if ( req.http.Upgrade ~ "(?i)websocket" ) {
    return (pipe);
  }

  # Domain Exclusion test for Ticket #232653
  if (req.http.host ~ "stats\.humanitarianresponse\.info" ) {
  	return (pass);
  }

  # Drupal exceptions, edit if we want to cache some AJAX/AHAH request.
  # Add here filters for never cache URLs such as Payment Gateway's callbacks.
  if ( req.url ~ "^/status\.php$"
    || req.url ~ "^/update\.php$"
    || req.url ~ "^/ooyala/ping$"
    || req.url ~ "^/admin/build/features"
    || req.url ~ "^/info/.*$"
    || req.url ~ "^/flag/.*$"
    || req.url ~ "^.*/ajax/.*$"
    || req.url ~ "^.*/ahah/.*$"
  ) {
    /* Do not cache these paths */
    return (pass);
  }
  if ( req.url ~ "^/system/files" ) {
    return (pipe);
  }

  # Do not store images or pdf documents
  if ( req.url ~ "(?i)\.(7z|avi|bz2|flv|gif|gz|jpe?g|mpe?g|mk[av]|mov|mp[34]|og[gm]|pdf|png|rar|swf|tar|tbz|tgz|woff2?|zip|xz)(\?.*)?$") {
    return (pass);
  }

  # sparql is acting as a webservice, and seems to act weird when passed.
  # Just relay the bytes.
  if (req.url ~ "^/sparql") {
    return (pipe);
  }

  # Althought Varnish 3 handles gziped content itself by default, just to be
  # sure we want to remove Accept-Encoding for some compressed formats.
  # See https://www.varnish-cache.org/docs/4.0/phk/gzip.html#what-does-http-gzip-support-do
  # See https://www.varnish-cache.org/docs/4.0/users-guide/compression.html
  # See https://www.varnish-cache.org/docs/4.0/reference/varnishd.html?highlight=http_gzip_support
  # See (for older configs) https://www.varnish-cache.org/trac/wiki/VCLExampleNormalizeAcceptEncoding
  if ( req.http.Accept-Encoding ) {
    if ( req.url ~ "(?i)\.(7z|avi|bz2|flv|gif|gz|jpe?g|mpe?g|mk[av]|mov|mp[34]|og[gm]|pdf|png|rar|swf|tar|tbz|tgz|woff2?|zip|xz)(\?.*)?$"
    ) {
      /* Already compressed formats, no sense trying to compress again */
      unset req.http.Accept-Encoding;
    }
  }

  # Add a debug header only on request.
  unset req.http.X-debug;
  if ( req.http.cookie ~ "hrinfo-debug" ) {
    set req.http.X-debug = "true";
  }

  # We could add here a custom header grouping User-agent families.
  # Generic URL manipulation.
  # Remove Google Analytics added parameters, useless for our backends.
  if ( req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=" ) {
    set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
    set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
    set req.url = regsub(req.url, "\?&", "?");
    set req.url = regsub(req.url, "\?$", "");
  }
  # Strip anchors, server doesn't need it.
  if ( req.url ~ "\#" ) {
    set req.url = regsub(req.url, "\#.*$", "");
  }
  # Strip a trailing ? if it exists
  if ( req.url ~ "\?$" ) {
    set req.url = regsub(req.url, "\?$", "");
  }
  # Normalize the querystring arguments
  set req.url = std.querysort(req.url);

  # Remove all cookies that Drupal doesn't need to know about. ANY remaining
  # cookie will cause the request to pass-through to Apache. For the most part
  # we always set the NO_CACHE cookie after any POST request, disabling the
  # Varnish cache temporarily. The session cookie allows all authenticated users
  # to pass through as long as they're logged in.
  if (req.http.Cookie) {
    # identify language cookie
    if (req.http.cookie ~ "language=") {
      #unset all the cookie from request except language
      set req.http.X-Varnish-Language = regsub(req.http.cookie, "(.*?)(language=)([^;]*)(.*)$", "\3");
    }

    set req.http.Cookie = ";" + req.http.Cookie;
    set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
    set req.http.Cookie = regsuball(req.http.Cookie, ";(S?SESS[a-z0-9]+|NO_CACHE)=", "; \1=");
    set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

    if (req.http.Cookie == "") {
      # If there are no remaining cookies, remove the cookie header. If there
      # aren't any cookie headers, Varnish's default behavior will be to cache
      # the page.
      unset req.http.Cookie;
    }
    else {
      # If there are any cookies left (a session or NO_CACHE cookie), do not
      # cache the page. Pass it on to Apache directly.
      return (pass);
    }
  }

  # We make sure no built-in logic is processed after ours returning
  # inconditionally.
  return (hash);
}

# vcl_hit: Called after a cache lookup if the requested document was found in
# the cache.
# See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-built-in-subs.html#vcl-hit
sub vcl_hit {
  if ( obj.ttl >= 0s ) {
    // A pure unadultered hit, deliver it
    return (deliver);
  }
  # Allow varnish to serve up stale content if it is responding slowly
  # See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-grace.html
  # See https://www.varnish-software.com/blog/grace-varnish-4-stale-while-revalidate-semantics-varnish
  if ( obj.ttl + obj.grace > 0s ) {
    // Object is in grace, deliver it
    // Automatically triggers a background fetch
    set req.http.grace = "normal";
    return (deliver);
  }
  # We make sure no built-in logic is processed after ours returning
  # inconditionally.
  return (fetch);
}

# vcl_deliver: Called before an object is delivered to the client
# See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-built-in-subs.html#vcl-deliver
sub vcl_deliver {
  if (req.http.X-Debug) {
    # See https://www.varnish-software.com/blog/grace-varnish-4-stale-while-revalidate-semantics-varnish
    set resp.http.grace = req.http.grace;

    # In Varnish 4 the obj.hits counter behaviour has changed (see bug 1492), so
    # we use a different method: if X-Varnish contains only 1 id, we have a miss,
    # if it contains more (and therefore a space), we have a hit.
    if ( resp.http.x-varnish ~ " " ) {
      set resp.http.X-Cache = "HIT";
      # Since in Varnish 4 the behaviour of obj.hits changed, this might not be
      # accurate.
      # See https://www.varnish-cache.org/trac/ticket/1492
      set resp.http.X-Cache-Hits = obj.hits;
    } else {
      set resp.http.X-Cache = "MISS";
      /* Show the results of cookie sanitization */
      set resp.http.X-Cookie = req.http.Cookie;
    }
    # See https://www.varnish-software.com/blog/grace-varnish-4-stale-while-revalidate-semantics-varnish
    set resp.http.grace = req.http.grace;

    # Add the Varnish server hostname
    set resp.http.X-Varnish-Server = server.hostname;
  }

  # Remove some headers: PHP version
  unset resp.http.X-Powered-By;

  # Remove some headers: Apache version & OS
  unset resp.http.Server;
  unset resp.http.X-Drupal-Cache;
  unset resp.http.X-Varnish;
  unset resp.http.Via;
  unset resp.http.X-Generator;

  return (deliver);
}

# vcl_synth: Called to deliver a synthetic object. A synthetic object is
# generated in VCL, not fetched from the backend. It is typically contructed
# using the synthetic() function.
# See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-built-in-subs.html#vcl-synth
sub vcl_synth {
  # Handle custom redirections
  call perm_redirections_synth;

  if ( resp.status != 200 ) {
    set resp.http.Retry-After = "5";
  }

  # We make sure no built-in logic is processed after ours returning
  # inconditionally.
  return (deliver);
}

# vcl_backend_response: Called after the response headers has been successfully
# retrieved from the backend.
# See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-built-in-subs.html#vcl-backend-response
sub vcl_backend_response {
  # Varnish will cache objects with response codes:
  #   200, 203, 300, 301, 302, 307, 404 & 410.
  # SeeV3 https://www.varnish-software.com/static/book/VCL_Basics.html#the-initial-value-of-beresp-ttl

  # Request retrial
  if ( beresp.status == 500
    || beresp.status == 503
  ) {
    return (retry);
  }

  # Move to the piwik container.
  if (bereq.http.host == "stats.humanitarianresponse.info") {
      set beresp.uncacheable = true;
      return (deliver);
  }

  # Grace mode.
  # See https://www.varnish-cache.org/docs/4.0/users-guide/vcl-grace.html
  # See https://www.varnish-software.com/blog/grace-varnish-4-stale-while-revalidate-semantics-varnish
  set beresp.grace = 1d;

  #Since we strip cookies, if for some reason these give us something that
  #runs PHP (e.g. a 404), if we don't strip out the set-cookie, we'll be
  #treated as an anonymous user and given a fresh cookie.
  if ( bereq.url ~ "(?i)\.(bz2|css|eot|gif|gz|html?|ico|jpe?g|js|mp3|ogg|otf|pdf|png|rar|svg|swf|tbz|tgz|ttf|woff2?|zip)(\?(itok=)?[a-z0-9_=\.\-]+)?$"
  ) {
    unset beresp.http.set-cookie;
  }

  # We want built-in logic to be processed after ours so we don't call return.
}

# Redirections subroutine.
sub perm_redirections_recv {
  if ( req.http.host ~ "^humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info" + req.url)
    );
  }
  if ( req.http.host ~ "^car.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/fr/operations/central-african-republic" + req.url)
    );
  }
  if ( req.http.host ~ "^philippines.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/philippines" + req.url)
    );
  }
  if ( req.http.host ~ "^wca.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/west-and-central-africa" + req.url)
    );
  }
  if ( req.http.host ~ "^mali.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/fr/operations/mali" + req.url)
    );
  }
  if ( req.http.host ~ "^southsudan.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/south-sudan" + req.url)
    );
  }
  if ( req.http.host ~ "^afg.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/afghanistan" + req.url)
    );
  }
  if ( req.http.host ~ "^cod.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/applications/data" + req.url)
    );
  }
  if ( req.http.host ~ "^haiti.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/haiti" + req.url)
    );
  }
  if ( req.http.host ~ "^pak.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/pakistan" + req.url)
    );
  }
  if ( req.http.host ~ "^yemen.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/yemen" + req.url)
    );
  }
  if ( req.http.host ~ "^sudan.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/sudan" + req.url)
    );
  }
  if ( req.http.host ~ "^kenya.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/kenya" + req.url)
    );
  }
  if ( req.http.host ~ "^rosa.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/southern-africa" + req.url)
    );
  }
  if ( req.http.host ~ "^assessments.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/programme-cycle/space/page/assessments-overview" + req.url)
    );
  }
  if ( req.http.host ~ "^syria.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/syria" + req.url)
    );
  }
  if ( req.http.host ~ "^zw.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/zimbabwe" + req.url)
    );
  }
  if ( req.http.host ~ "^ethiopia.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/ethiopia" + req.url)
    );
  }
  if ( req.http.host ~ "^chad.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/fr/operations/chad" + req.url)
    );
  }
  if ( req.http.host ~ "^somalia.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/somalia" + req.url)
    );
  }
  if ( req.http.host ~ "^indonesia.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/indonesia" + req.url)
    );
  }
  if ( req.http.host ~ "^ir.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/applications/ir" + req.url)
    );
  }
  if ( req.http.host ~ "^stima.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/stima" + req.url)
    );
  }
  if ( req.http.host ~ "^pht.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/pacific-region" + req.url)
    );
  }
  if ( req.http.host ~ "^er.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/clusters/early-recovery/page" + req.url)
    );
  }
  if ( req.http.host ~ "^niger.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/niger" + req.url)
    );
  }
  if ( req.http.host ~ "^rdc.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/fr/operations/democratic-republic-congo" + req.url)
    );
  }
  if ( req.http.host ~ "^help.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/help" + req.url)
    );
  }
  if ( req.http.host ~ "^education.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/coordination/clusters/education" + req.url)
    );
  }
  if ( req.http.host ~ "^ea.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/eastern-africa" + req.url)
    );
  }
  if ( req.http.host ~ "^iraq.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/iraq" + req.url)
    );
  }
  if ( req.http.host ~ "^imwg.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/topics/imwg" + req.url)
    );
  }
  if ( req.http.host ~ "^ebola.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/disaster/ep-2014-000041-gin" + req.url)
    );
  }
  if ( req.http.host ~ "^cambodia.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/cambodia" + req.url)
    );
  }
  if ( req.http.host ~ "^data.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/applications/data" + req.url)
    );
  }
  if ( req.http.host ~ "^nepal.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/nepal" + req.url)
    );
  }
  if ( req.http.host ~ "^ahh.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/topics/africa-humanitarian-hub" + req.url)
    );
  }
  if ( req.http.host ~ "^nigeria.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/operations/nigeria" + req.url)
    );
  }
  if ( req.http.host ~ "^hpc.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info/programme-cycle/space" + req.url)
    );
  }
  if ( req.http.host ~ "^kiosk.humanitarianresponse.info" ) {
    return (
      synth(751, "https://www.humanitarianresponse.info" + req.url)
    );
  }
}

# Redirections subroutine.
sub perm_redirections_synth {
  if ( resp.status == 751 ) {
    set resp.http.Location = resp.reason;
    set resp.status = 301;
    set resp.reason = "Moved Permanently";
    return (deliver);
  }
}
