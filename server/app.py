#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt

from config import app, db, api
from models import User, Recipe

bycrypt = Bcrypt()

class Signup(Resource):
    def post(self):
        data = request.get_json()
        errors = {}
        if not data.get('username'):
            errors['username'] = 'Username is required.'
        if not data.get('password'):
            errors['password'] = 'Password is required.'
        
        if errors:
            return make_response(jsonify({'errors': errors}), 422)
        
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return make_response(jsonify({'errors': {'username': 'Username already exists.'}}), 422)

        new_user = User(
            username=data['username'],
            image_url=data.get('image_url'),
            bio=data.get('bio')
        )
        new_user.password_hash = data['password']
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id

        return make_response(
                jsonify({
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }), 201)

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return make_response(jsonify({
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }), 200)
            else:
                return make_response(jsonify({"error": "User not found"}), 404)
        else:
            return make_response(jsonify({"error": "Anauthorized. Please log in"}), 401)
        
class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return make_response(jsonify({"error": "username and password required"}), 400)
        
        user = User.query.filter_by(username=username).first()
        if user and bycrypt.check_password_hash(user._password_hash, password):
            session['user_id'] = user.id
            
            return make_response(jsonify({
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }), 200)
        else:
            return make_response(jsonify({'error': 'Invalid username or password'}), 401)

class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session['user_id'] is not None:
            session['user_id'] = None
            return '', 204
        else:
            return make_response(jsonify({'error': 'Unauthorized'}), 401)

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' in session and session['user_id'] is not None:       
            recipes = Recipe.query.all()
            output = []
            for recipe in recipes:
                output.append({
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username,
                        'image_url': recipe.user.image_url,
                        'bio': recipe.user.bio
                    }
                })
            
            return make_response(jsonify(output), 200)
        else:
            return make_response(jsonify({'error': 'Unauthorized'}), 401 )
    
    def post(self):
        if 'user_id' not in session or session['user_id'] is None:
            return make_response(jsonify({'error': 'Unauthorized'}), 401)

        data = request.get_json()
        if not data or not all(key in data for key in ['title', 'instructions', 'minutes_to_complete']):
            return make_response(jsonify({'error': 'Invalid input'}), 422)

        if len(data['instructions']) < 50:
            return make_response(jsonify({'error': 'Instructions must be at least 50 characters long'}), 422)

        new_recipe = Recipe(
            title=data['title'],
            instructions=data['instructions'],
            minutes_to_complete=data['minutes_to_complete'],
            user_id=session['user_id']
        )
        db.session.add(new_recipe)
        db.session.commit()

        return make_response(jsonify(new_recipe), 201)
            

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)