const { Client } = require('pg')
const { getDatabaseUri } = require('./config')

let db

if (process.env.NODE_ENV === 'production') {
	db = new Client({
		connectionString: 'placeholder',
		ssl: {
			rejectUnauthorized: false,
		},
	})
} else {
	db = new Client({
		connectionString: 'placeholder',
	})
}

db.connect()

module.exports = db
