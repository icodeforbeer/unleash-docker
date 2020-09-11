"use strict";

var bodyParser = require("body-parser");
var passport = require("passport");
var config = require("./config");
var unleash = require("unleash-server");
var log4js = require("log4js");

const { User, AuthenticationRequired } = unleash;

// Start QuickStart here
var OIDCStrategy = require("passport-azure-ad").OIDCStrategy;

log4js.configure({
  appenders: {
    console: { type: "console" },
  },
  categories: {
    default: { appenders: ["console"], level: log4js.levels.DEBUG.levelStr },
  },
});
var log = log4js.getLogger("Unleash Feature Flagging");

/******************************************************************************
 * Set up passport in the app
 ******************************************************************************/

// array to hold logged in users
var users = [];

var findByOid = (oid, fn) => {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    log.info("we are using user: ", user);
    if (user.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

passport.use(
  new OIDCStrategy(
    {
      identityMetadata: config.creds.identityMetadata,
      clientID: config.creds.clientID,
      responseType: config.creds.responseType,
      responseMode: config.creds.responseMode,
      redirectUrl: config.creds.redirectUrl,
      allowHttpForRedirectUrl: config.creds.allowHttpForRedirectUrl,
      clientSecret: config.creds.clientSecret,
      validateIssuer: config.creds.validateIssuer,
      isB2C: config.creds.isB2C,
      issuer: config.creds.issuer,
      passReqToCallback: config.creds.passReqToCallback,
      scope: config.creds.scope,
      loggingLevel: config.creds.loggingLevel,
      nonceLifetime: config.creds.nonceLifetime,
      nonceMaxAmount: config.creds.nonceMaxAmount,
      useCookieInsteadOfSession: config.creds.useCookieInsteadOfSession,
      cookieEncryptionKeys: config.creds.cookieEncryptionKeys,
      clockSkew: config.creds.clockSkew,
    },
    function (iss, sub, profile, accessToken, refreshToken, done) {
      if (!profile.oid) {
        return done(new Error("No oid found"), null);
      }
      // asynchronous verification, for effect...
      process.nextTick(function () {
        findByOid(profile.oid, function (err, user) {
          if (err) {
            return done(err);
          }
          if (!user) {
            // "Auto-registration"
            users.push(profile);
            return done(
              null,
              new User({
                name: profile.displayName,
                email: profile._json.email,
              })
            );
          }
          return done(
            null,
            new User({
              name: user.displayName,
              email: user._json.email,
            })
          );
        });
      });
    }
  )
);

//-----------------------------------------------------------------------------
// Config the app, include middlewares
//-----------------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  return res
    .status("401")
    .json(
      new AuthenticationRequired({
        path: "/api/admin/login",
        type: "custom",
        message: `Please login. 
                      Click the button and follow the instructions.`,
      })
    )
    .end();
}

function configureApp(app) {
  app.use(bodyParser.urlencoded({ extended: true }));

  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());

  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));

  //-----------------------------------------------------------------------------
  // Set up the route controller
  //
  // 1. For 'login' route and 'returnURL' route, use `passport.authenticate`.
  // This way the passport middleware can redirect the user to login page, receive
  // id_token etc from returnURL.
  //
  // 2. For the routes you want to check if user is already logged in, use
  // `ensureAuthenticated`. It checks if there is an user stored in session, if not
  // it will call `passport.authenticate` to ask for user to log in.
  //-----------------------------------------------------------------------------
  app.get(
    "/api/admin/login",
    function (req, res, next) {
      console.log(`login: ${req.user}`);
      passport.authenticate("azuread-openidconnect", {
        session: false,
        response: res, // required
        failureRedirect: "/api/admin/error-login",
      })(req, res, next);
    },
    function (req, res) {
      log.info("Login was called in the Sample");
      res.redirect("/");
    }
  );

  // Only needed if using 'query' as responseMode in OIDCStrategy
  //   app.get(
  //     "/api/auth/callback",
  //     function (req, res, next) {
  //       passport.authenticate("azuread-openidconnect", {
  //         response: res, // required
  //         failureRedirect: "/",
  //       })(req, res, next);
  //     },
  //     function (req, res) {
  //       log.info("We received a return from AzureAD.");
  //       res.redirect("/");
  //     }
  //   );

  app.post(
    "/api/auth/callback",
    function (req, res, next) {
      log.info(`callback: ${req}`);
      passport.authenticate("azuread-openidconnect", {
        response: res, // required
        failureRedirect: "/",
      })(req, res, next);
    },
    function (req, res) {
      log.info("We received a return from AzureAD.");
      res.redirect("/");
    }
  );

  app.use("/api/admin/", ensureAuthenticated);
}

unleash.start({
  // databaseUrl: 'postgres://unleash_user:passord@localhost:5432/unleash',
  adminAuthentication: "custom",
  port: "4242",
  preRouterHook: configureApp,
  enableRequestLogger: true,
  getLogger: log4js.getLogger,
});
