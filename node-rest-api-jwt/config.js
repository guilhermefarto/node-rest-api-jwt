module.exports = {
	defaultPort: 3000,
	timezone: 'America/Sao_Paulo',
	jwtSecret: 'example-token-secret-key',
	jwtExpiresIn: '30m', // '30m' = minutes (or '2h' = 2 hours or '3d' = 3 days)
	// jwtExpiresIn: '1m', // to simulate a quicker token expiration
	jwtSession: {
		session: false
	},
	jwtUsesRSA: true
};