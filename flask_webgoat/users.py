import sqlite3

from flask import Blueprint, jsonify, session, request

from . import query_db

bp = Blueprint("users", __name__)


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"})
    
    username = request.form.get("username")
    password = request.form.get("password")
    access_level_str = request.form.get("access_level")
    
    if username is None or password is None or access_level_str is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    
    # Enhanced input validation for username
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"error": "Username can only contain alphanumeric characters and underscores"}), 400
        
    if len(password) < 3:
        return (
            jsonify({"error": "the password needs to be at least 3 characters long"}),
            402,
        )
    
    # Access level validation
    try:
        access_level = int(access_level_str)
        if access_level not in [0, 1, 2]:  # Define allowed access levels
            raise ValueError("Invalid access level")
    except ValueError:
        return jsonify({"error": "Invalid access level value"}), 400
        
    # Hash password before storing
    hashed_password = generate_password_hash(password)
    
    try:
        # Using ORM approach for better security and abstraction
        from models import User
        new_user = User(username=username, password=hashed_password, access_level=access_level)
        db.session.add(new_user)
        db.session.commit()
        
        # Fallback to parameterized query approach if ORM fails for any reason
        # execute_safe_query("INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)", 
        #                     [username, hashed_password, access_level], 
        #                     False, True)
                        
        return jsonify({"success": True})
    except Exception as err:
        # Secure error logging
        app.logger.error(f"Database error when creating user: {str(err)}")
        return jsonify({"error": "Could not create user due to a system error"}), 500

# Added helper function for prepared statement pattern
def execute_safe_query(query, params=None, fetch=False, commit=False):
    """Execute SQL with built-in safety measures"""
    try:
        return query_db(query, params, fetch, commit)
    except sqlite3.Error as err:
        # Log error details securely
        app.logger.error(f"Database error: {str(err)}")
        raise

        query_db(query, [], False, True)
        return jsonify({"success": True})
    except sqlite3.Error as err:
        return jsonify({"error": "could not create user:" + err})
