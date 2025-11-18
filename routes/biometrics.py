"""
Biometric authentication blueprint for Stanbic Bank Uganda Online Banking System.
Uses browser-based WebAuthn API for biometric authentication (fingerprint, face, security keys).
Compatible with Python 3.11 and 3.12.

Requirements:
- Python 3.11 or 3.12
- See requirements.txt for package dependencies
"""

from flask import Blueprint, request, jsonify, render_template, session
from flask_login import login_required, current_user, login_user
from models.user import User, db
import base64
import json
import secrets
import logging
from datetime import datetime, timedelta

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Blueprint ---
biometrics_bp = Blueprint('biometrics', __name__, url_prefix='/biometrics')

# Store temporary challenges with expiration (use Redis or secure store in production)
challenges = {}


def clean_expired_challenges():
    """Remove expired challenges older than 5 minutes"""
    current_time = datetime.now()
    expired_keys = [
        key for key, (challenge, timestamp) in challenges.items()
        if current_time - timestamp > timedelta(minutes=5)
    ]
    for key in expired_keys:
        del challenges[key]


def get_rp_id(request_host):
    """
    Get the Relying Party ID from the request host.
    Handles localhost, IP addresses, and domain names correctly.
    
    Args:
        request_host (str): The host from request
        
    Returns:
        str: Properly formatted RP ID
    """
    try:
        # Remove port if present
        host = request_host.split(':')[0] if ':' in request_host else request_host
        
        # Check if it's localhost or 127.0.0.1
        if host in ['localhost', '127.0.0.1', '0.0.0.0']:
            return 'localhost'
        
        # Check if it's a local IP address
        if host.startswith('192.168.') or host.startswith('10.') or host.startswith('172.'):
            return 'localhost'
        
        # For domain names, return as is
        return host
    except Exception as e:
        logger.error(f"Error getting RP ID: {e}")
        return 'localhost'


def get_origin(request_obj):
    """
    Get the origin URL from the request.
    Ensures proper formatting for WebAuthn.
    
    Args:
        request_obj: Flask request object
        
    Returns:
        str: Properly formatted origin URL
    """
    try:
        scheme = request_obj.scheme
        host = request_obj.host
        
        # Normalize localhost
        host_parts = host.split(':')
        if host_parts[0] in ['127.0.0.1', '0.0.0.0']:
            host = 'localhost' + (f':{host_parts[1]}' if len(host_parts) > 1 else '')
        
        return f"{scheme}://{host}"
    except Exception as e:
        logger.error(f"Error getting origin: {e}")
        return f"{request_obj.scheme}://{request_obj.host}"


# ------------------------
# --- WebAuthn Routes ---
# ------------------------

@biometrics_bp.route('/setup')
@login_required
def setup_page():
    """Render the biometrics setup page"""
    try:
        return render_template('set_biometrics.html')
    except Exception as e:
        logger.error(f"Error rendering setup page: {e}")
        return jsonify({'success': False, 'error': 'Failed to load setup page'}), 500


@biometrics_bp.route('/generate_registration_options', methods=['POST'])
@login_required
def generate_registration_options_route():
    """Generate WebAuthn registration options for biometric authentication"""
    try:
        user = current_user
        
        # Generate and store challenge with timestamp
        challenge = secrets.token_bytes(32)
        challenges[user.id] = (challenge, datetime.now())
        
        # Clean up expired challenges
        clean_expired_challenges()

        # Get proper RP ID and origin
        rp_id = get_rp_id(request.host)
        
        logger.info(f"Registration - User: {user.username}, Host: {request.host}, RP ID: {rp_id}")

        # Generate registration options
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="Stanbic Bank Uganda",
            user_id=str(user.id).encode('utf-8'),
            user_name=user.username,
            user_display_name=f"{user.first_name} {user.last_name}",
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256
            ],
            timeout=60000
        )

        logger.info(f"Generated registration options for user {user.username}")
        
        # Convert options to JSON
        options_json = json.loads(options_to_json(options))
        
        return jsonify(options_json), 200
        
    except Exception as e:
        logger.error(f"Error generating registration options: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Registration failed: {str(e)}'}), 500


@biometrics_bp.route('/register_biometric', methods=['POST'])
@login_required
def register_biometric():
    """Verify and store biometric credential (fingerprint, face, or security key)"""
    try:
        user = current_user
        data = request.get_json()
        
        if not data:
            logger.warning(f"No data provided for user {user.username}")
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        # Get and validate challenge
        challenge_data = challenges.get(user.id)
        if not challenge_data:
            logger.warning(f"No challenge found for user {user.username}")
            return jsonify({'success': False, 'error': 'No challenge found or challenge expired'}), 400
        
        expected_challenge = challenge_data[0]

        # Get proper RP ID and origin
        rp_id = get_rp_id(request.host)
        origin = get_origin(request)
        
        logger.info(f"Verification - User: {user.username}, Origin: {origin}, RP ID: {rp_id}")

        # Verify registration response
        verification = verify_registration_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=rp_id
        )

        # Prepare credential data
        credential_id = verification.credential_id
        credential_data = {
            'credential_id': base64.b64encode(credential_id).decode('utf-8'),
            'public_key': base64.b64encode(verification.credential_public_key).decode('utf-8'),
            'sign_count': verification.sign_count,
            'credential_type': verification.credential_type,
            'aaguid': base64.b64encode(verification.aaguid).decode('utf-8') if verification.aaguid else None,
            'rp_id': rp_id,
            'registered_at': datetime.now().isoformat()
        }

        # Store the credential
        user.fingerprint_token = json.dumps(credential_data)
        user.biometric_enabled = True
        db.session.commit()

        # Clean up challenge
        if user.id in challenges:
            del challenges[user.id]

        logger.info(f"Biometric credential registered successfully for user {user.username}")
        
        return jsonify({
            'success': True, 
            'message': 'Biometric authentication registered successfully',
            'credential_type': verification.credential_type
        }), 200
        
    except Exception as e:
        logger.error(f"Error registering biometric: {str(e)}", exc_info=True)
        
        # Clean up challenge on error
        if hasattr(current_user, 'id') and current_user.id in challenges:
            del challenges[current_user.id]
            
        return jsonify({'success': False, 'error': f'Registration failed: {str(e)}'}), 500


# Legacy route for backwards compatibility
@biometrics_bp.route('/register_fingerprint', methods=['POST'])
@login_required
def register_fingerprint():
    """Legacy endpoint - redirects to register_biometric"""
    return register_biometric()


@biometrics_bp.route('/generate_authentication_options', methods=['POST'])
def generate_authentication_options_route():
    """Generate WebAuthn authentication options for login"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        username = data.get('username')
        
        if not username:
            return jsonify({'success': False, 'error': 'Username required'}), 400

        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            logger.warning(f"User not found: {username}")
            return jsonify({'success': False, 'error': 'User not found'}), 404
            
        if not user.biometric_enabled or not user.fingerprint_token:
            logger.warning(f"Biometric not enabled for user: {username}")
            return jsonify({'success': False, 'error': 'Biometric authentication not available'}), 400

        # Generate challenge
        challenge = secrets.token_bytes(32)
        challenges[user.id] = (challenge, datetime.now())
        
        # Clean up expired challenges
        clean_expired_challenges()

        # Parse stored credential
        try:
            credential_data = json.loads(user.fingerprint_token)
            credential_id = base64.b64decode(credential_data['credential_id'])
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Invalid credential data for user {username}: {e}")
            return jsonify({'success': False, 'error': 'Invalid credential data'}), 500

        # Get proper RP ID
        rp_id = get_rp_id(request.host)
        
        logger.info(f"Authentication options - User: {username}, Host: {request.host}, RP ID: {rp_id}")

        # Generate authentication options
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[{
                'type': 'public-key', 
                'id': credential_id,
                'transports': ['internal', 'hybrid']
            }],
            user_verification=UserVerificationRequirement.REQUIRED,
            timeout=60000
        )

        # Store user ID in session for verification
        session['biometric_user_id'] = user.id
        session.modified = True
        
        logger.info(f"Generated authentication options for user {username}")
        
        # Convert to JSON
        options_json = json.loads(options_to_json(options))
        
        return jsonify(options_json), 200
        
    except Exception as e:
        logger.error(f"Error generating authentication options: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Authentication setup failed: {str(e)}'}), 500


@biometrics_bp.route('/verify_biometric', methods=['POST'])
def verify_biometric():
    """Verify biometric authentication (fingerprint, face, or security key)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Get user from session
        user_id = session.get('biometric_user_id')
        
        if not user_id:
            logger.warning("No authentication session found")
            return jsonify({'success': False, 'error': 'No authentication session'}), 400

        # Find user
        user = User.query.get(user_id)
        
        if not user or not user.fingerprint_token:
            logger.warning(f"Invalid user or missing credential: {user_id}")
            return jsonify({'success': False, 'error': 'Invalid user or credential'}), 400

        # Parse credential data
        try:
            credential_data = json.loads(user.fingerprint_token)
            credential_public_key = base64.b64decode(credential_data['public_key'])
            credential_id = base64.b64decode(credential_data['credential_id'])
            sign_count = credential_data['sign_count']
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Error parsing credential data: {e}")
            return jsonify({'success': False, 'error': 'Invalid credential data'}), 500

        # Get and validate challenge
        challenge_data = challenges.get(user_id)
        if not challenge_data:
            logger.warning(f"No challenge found for user {user_id}")
            return jsonify({'success': False, 'error': 'No challenge found or challenge expired'}), 400
        
        expected_challenge = challenge_data[0]

        # Get proper RP ID and origin
        rp_id = get_rp_id(request.host)
        origin = get_origin(request)
        
        logger.info(f"Verification - User: {user.username}, Origin: {origin}, RP ID: {rp_id}")

        # Verify authentication response
        verification = verify_authentication_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count
        )

        # Update sign count
        credential_data['sign_count'] = verification.new_sign_count
        user.fingerprint_token = json.dumps(credential_data)
        db.session.commit()

        # Clean up
        if user_id in challenges:
            del challenges[user_id]
        session.pop('biometric_user_id', None)

        # Log the user in
        login_user(user, remember=True)

        logger.info(f"Biometric authentication successful for user {user.username}")
        
        return jsonify({
            'success': True, 
            'user_id': user.id, 
            'username': user.username,
            'message': 'Authentication successful'
        }), 200
        
    except Exception as e:
        logger.error(f"Error verifying biometric: {str(e)}", exc_info=True)
        
        # Clean up on error
        user_id = session.get('biometric_user_id')
        if user_id and user_id in challenges:
            del challenges[user_id]
        session.pop('biometric_user_id', None)
        
        return jsonify({'success': False, 'error': f'Verification failed: {str(e)}'}), 500


# Legacy route for backwards compatibility
@biometrics_bp.route('/verify_fingerprint', methods=['POST'])
def verify_fingerprint():
    """Legacy endpoint - redirects to verify_biometric"""
    return verify_biometric()


@biometrics_bp.route('/disable', methods=['POST'])
@login_required
def disable_biometrics():
    """Disable biometric authentication"""
    try:
        user = current_user
        
        # Clear biometric data
        user.biometric_enabled = False
        user.fingerprint_token = None
        
        # Clear face_token if it exists (for backwards compatibility)
        if hasattr(user, 'face_token'):
            user.face_token = None
            
        db.session.commit()

        logger.info(f"Biometric authentication disabled for user {user.username}")
        
        return jsonify({
            'success': True, 
            'message': 'Biometric authentication disabled successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error disabling biometrics: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Failed to disable biometrics: {str(e)}'}), 500


@biometrics_bp.route('/status', methods=['GET'])
@login_required
def biometric_status():
    """Get current biometric authentication status"""
    try:
        user = current_user
        has_credential = user.fingerprint_token is not None
        
        credential_info = None
        if has_credential:
            try:
                credential_data = json.loads(user.fingerprint_token)
                credential_info = {
                    'credential_type': credential_data.get('credential_type', 'public-key'),
                    'has_aaguid': credential_data.get('aaguid') is not None,
                    'rp_id': credential_data.get('rp_id', 'unknown'),
                    'registered_at': credential_data.get('registered_at', 'unknown')
                }
            except Exception as e:
                logger.warning(f"Error parsing credential info: {e}")
                credential_info = {'error': 'Invalid credential data'}
        
        return jsonify({
            'success': True,
            'biometric_enabled': user.biometric_enabled,
            'has_credential': has_credential,
            'credential_info': credential_info,
            'webauthn_available': True,
            'current_rp_id': get_rp_id(request.host),
            'current_origin': get_origin(request)
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting biometric status: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@biometrics_bp.route('/info', methods=['GET'])
def biometric_info():
    """Get information about supported biometric methods"""
    return jsonify({
        'success': True,
        'authentication_method': 'WebAuthn (Browser-based)',
        'current_rp_id': get_rp_id(request.host),
        'current_origin': get_origin(request),
        'supported_authenticators': [
            {
                'type': 'platform',
                'name': 'Built-in Biometrics',
                'examples': [
                    'Touch ID (Apple devices)',
                    'Face ID (Apple devices)',
                    'Windows Hello (Windows devices)',
                    'Fingerprint sensors (Android/laptops)',
                    'Facial recognition (Android)'
                ]
            },
            {
                'type': 'cross-platform',
                'name': 'Security Keys',
                'examples': [
                    'YubiKey',
                    'Google Titan Security Key',
                    'USB/NFC security keys'
                ]
            }
        ],
        'browser_support': {
            'chrome': 'Supported (v67+)',
            'firefox': 'Supported (v60+)',
            'safari': 'Supported (v13+)',
            'edge': 'Supported (v18+)'
        },
        'security_features': [
            'Private keys never leave device',
            'Resistant to phishing',
            'No password transmission',
            'Replay attack protection',
            'User verification required'
        ]
    }), 200


# Health check endpoint
@biometrics_bp.route('/health', methods=['GET'])
def health_check():
    """Check if biometric authentication service is running"""
    return jsonify({
        'success': True,
        'service': 'biometric_authentication',
        'status': 'operational',
        'method': 'WebAuthn (Browser-based)',
        'rp_id': get_rp_id(request.host),
        'origin': get_origin(request),
        'timestamp': datetime.now().isoformat(),
        'active_challenges': len(challenges)
    }), 200


# Debug endpoint (remove in production)
@biometrics_bp.route('/debug', methods=['GET'])
@login_required
def debug_info():
    """Debug information for troubleshooting"""
    return jsonify({
        'request_host': request.host,
        'request_scheme': request.scheme,
        'rp_id': get_rp_id(request.host),
        'origin': get_origin(request),
        'remote_addr': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'is_secure': request.is_secure,
        'user_id': current_user.id,
        'username': current_user.username,
        'biometric_enabled': current_user.biometric_enabled,
        'has_credential': current_user.fingerprint_token is not None,
        'active_challenges': len(challenges)
    }), 200


# Error handlers
@biometrics_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'success': False, 'error': 'Bad request'}), 400


@biometrics_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'success': False, 'error': 'Unauthorized'}), 401


@biometrics_bp.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Not found'}), 404


@biometrics_bp.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500