var config = require('./config.js');
var messages = require('./messages.js');

var extend = require('util')._extend;

// var moment = require('moment');
var moment = require('moment-timezone');
var _ = require('lodash');
var fs = require('fs');
var express = require('express');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');

var passport = require('passport');
var passportJWT = require('passport-jwt');

var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

var app = express();

if (config.jwtUsesRSA) {
	var privateKey = fs.readFileSync(__dirname + '/keys/private.key');
	var publicKey = fs.readFileSync(__dirname + '/keys/public.pem');
}

var users = [{
	id: 1,
	user: 'guilherme.farto',
	password: 'pwd@123',
	mail: 'guilherme.farto@gmail.com'
}];

var params = {
	passReqToCallback: true,
	secretOrKey: config.jwtUsesRSA ? publicKey : config.jwtSecret,
	// jwtFromRequest: ExtractJwt.fromAuthHeader() // headers['authorization'] = JWT <token>
	jwtFromRequest: ExtractJwt.fromHeader('x-access-token') // headers['x-access-token'] = <token>
};

const SEPARATOR = '-'.repeat(50);

// var strategy = new JwtStrategy(params, function(payload, next) { // when params.passReqToCallback = false
var strategy = new JwtStrategy(params, function(req, payload, next) {
	console.log(SEPARATOR);

	console.log('Payload...........: ', JSON.stringify(payload));

	// console.log('Issued at.........: ', new Date(payload.iat * 1000).toLocaleString());
	// console.log('Expiration at.....: ', new Date(payload.exp * 1000).toLocaleString());

	console.log('Issued at.........: ', moment(payload.iat * 1000).tz(config.timezone).format()); // * 1000 = timestamp in milliseconds
	console.log('Expiration at.....: ', moment(payload.exp * 1000).tz(config.timezone).format());

	console.log(SEPARATOR);

	// Optional implementation (to perform an additional token check)
	try {
		let hasAuthorizationHeader = req.headers['authorization'] !== undefined;
		let hasAccessTokenHeader = req.headers['x-access-token'] !== undefined;

		if (hasAuthorizationHeader) {
			var token = req.headers['authorization'].split(' ').slice(1).join(' ');
		} else if (hasAccessTokenHeader) {
			var token = req.headers['x-access-token'];
		}

		// var decodedPayload = jwt.verify(token, 'invalid-secret-key');
		var decodedPayload = jwt.verify(token, params.secretOrKey, {
			algorithms: ['HS256', 'RS256']
		});

		console.log('Decoded payload...: ', JSON.stringify(decodedPayload));

		var decodedToken = jwt.decode(token, {
			complete: true
		});

		console.log('Decoded token.....: ', JSON.stringify(decodedToken));
		console.log('  Header..........: ', JSON.stringify(decodedToken.header));
		console.log('  Payload.........: ', JSON.stringify(decodedToken.payload));
		console.log('  Signature.......: ', JSON.stringify(decodedToken.signature));
		console.log(SEPARATOR);
	} catch (err) {
		console.error(err);

		next(null, false);
		return;
	}
	// Optional implementation

	var user = users[_.findIndex(users, {
		id: payload.id
	})];

	if (user) {
		next(null, user);
	} else {
		next(null, false);
	}
});

passport.use(strategy);

app.use(passport.initialize());

app.use(bodyParser.urlencoded({
	extended: true
}));

app.use(bodyParser.json());

app.get('/', function(req, res) {
	res.json(messages.serverOnline);
});

app.post('/login', function(req, res) {
	let jsonBody = req.body;

	if (jsonBody.user && jsonBody.password) {
		var user = jsonBody.user;
		var password = jsonBody.password;
	}

	var user = users[_.findIndex(users, {
		user: user
	})];

	if (!user) {
		res.status(401).json(extend(messages.failure, messages.invalidUser));
	} else if (user.password != jsonBody.password) {
		res.status(401).json(extend(messages.failure, messages.invalidPassword));
	} else {
		var payload = {
			id: user.id,
			mail: user.mail
		};

		// token pattern is equal to header + '.' + payload + '.' + signature
		if (config.jwtUsesRSA) {
			var token = jwt.sign(payload, privateKey, {
				expiresIn: config.jwtExpiresIn,
				algorithm: 'RS256'
			});
		} else {
			var token = jwt.sign(payload, params.secretOrKey, {
				expiresIn: config.jwtExpiresIn,
				algorithm: 'HS256'
			});
		}

		console.log('Token: ' + token);

		res.json(extend(messages.success, {
			token: token
		}));
	}
});

const authenticate = passport.authenticate('jwt', config.jwtSession);

app.get('/secret', authenticate, function(req, res) {
	res.json(extend(messages.successSecret, {
		user: req.user
	}));
});

app.get('/secretDebug',
	function(req, res, next) {
		let hasAuthorizationHeader = req.headers['authorization'] !== undefined;
		let hasAccessTokenHeader = req.headers['x-access-token'] !== undefined;

		if (hasAuthorizationHeader) {
			var token = req.headers['authorization'].split(' ').slice(1).join(' ');
		} else if (hasAccessTokenHeader) {
			var token = req.headers['x-access-token'];
		} else {
			res.status(401).json(extend(messages.failure, messages.shouldProvideToken));
			return;
		}

		var decodedToken = jwt.decode(token, {
			complete: true
		});

		var issuedAt = moment(decodedToken.payload.iat * 1000).tz(config.timezone).format();
		var expirationAt = moment(decodedToken.payload.exp * 1000).tz(config.timezone).format();

		req.authorization = {
			token: token,
			decodedToken: decodedToken,
			additional: {
				issuedAt: issuedAt,
				expirationAt: expirationAt
			}
		};

		next();
	},
	function(req, res) {
		res.json(extend(messages.debug, {
			authorization: req.authorization
		}));
	}
);

app.listen(config.defaultPort, function() {
	console.log('Example app listening on port', config.defaultPort);
});