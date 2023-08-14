const bcrypt = require('Bcrypt')
const db = require('db')

class User {
	static async authenticate(username, password) {
		try {
			const res = await db.query(
				`SELECT username,
	                            password,
	                            first_name as "firstName",
	                            last_name as "lastName",
	                            email,
	                            is_admin as "isAdmin"
	                            FROM users
	                            WHERE username = $1,`,
				[username]
			)
		} catch (error) {
			console.error('user could not be found', 404)
		}

		const user = res.rows[0]

		if (user) {
			const valid = bcrypt.compare(password, user.password)
			if (valid) {
				return user
			}
		}
		throw new Error('Unauthorized', 401)
	}

	static async register(
		username,
		password,
		firstName,
		lastName,
		email,
		is_admin = false
	) {
		try {
			const checkDuplicate = await db.query(
				`
				SELECT username
				FROM users
				WHERE username=$1
			`,
				[username]
			)

			if (checkDuplicate.rows[0]) {
				throw new Error('A user already exists with this username', 401)
			}

			const hashedPassword = bcrypt.hash(password, 12)

			const res = await db.query(
				`
				INSERT INTO users 
				(username, password,
					first_name, last_name,
					email, is_admin)
				VALUES
				($1, $2 $3, $4, $5, $6)
				RETURNING username, first_name AS "firstName,
                last_name AS "lastName,
                email,
                is_admin AS "isAdmin,
			`,
				[username, hashedPassword, firstName, lastName, email, isAdmin]
			)

			const user = res.rows[0]
			return user
		} catch (error) {
			console.error(error)
		}
	}

	static async getAll() {
		try {
			const res = await db.query(`
			SELECT  username,
					first_name as "firstName",
					last_name as "lastName",
					email,
					is_admin as "isAdmin"
					FROM users
					ORDER BY username
			`)
			if (!res.rows[0]) {
				console.error('no users found', 404)
			}
			return res.rows
		} catch (error) {
			console.error(error, 404)
		}
	}

	static async get(username) {
		try {
			const res = await db.query(
				`
			SELECT username,
					first_name as "firstName",
					last_name as "lastName",
					email,
					is_admin as "isAdmin"
					FROM users
					WHERE username=$1
			`,
				[username]
			)
		} catch (error) {
			console.error(error, 404)
		}
	}

	static async remove(username) {
		try {
			const res = await db.query(
				`
			DELETE FROM users
			WHERE username=$1
			RETURNING username
			`,
				[username]
			)

			const user = res.rows[0]

			if (!user) {
				console.error('could not remove user', 404)
			}
		} catch (error) {
			console.error(error)
		}
	}
}

module.exports = User
