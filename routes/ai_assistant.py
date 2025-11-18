"""
AI Assistant Blueprint for Stanbic Bank Uganda
FIXED VERSION - Resolves 404 errors and improves error handling
"""

from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_required, current_user
import os
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create blueprint with explicit URL prefix
ai_assistant_bp = Blueprint('ai_assistant', __name__, url_prefix='/ai-assistant')

# Initialize Gemini model
model = None
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

def init_gemini():
    """Initialize Gemini AI model"""
    global model
    if model is not None:
        return True
        
    if not GEMINI_API_KEY:
        logger.error("❌ GEMINI_API_KEY not found in environment")
        return False
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(
            "gemini-1.5-flash",
            generation_config={
                "temperature": 0.9,
                "top_p": 0.95,
                "top_k": 40,
                "max_output_tokens": 500,
            }
        )
        logger.info("✅ Gemini 1.5 Flash initialized successfully")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to initialize Gemini: {e}")
        return False

# Initialize on import
init_gemini()

# Banking context for AI
BANKING_CONTEXT = """You are Alex, a friendly AI banking assistant for Stanbic Bank Uganda. 

PERSONALITY:
- Warm, helpful, and professional
- Use emojis occasionally (💰 💳 📱 ✅)
- Keep responses under 150 words
- Be conversational and empathetic

STANBIC BANK SERVICES:
- Current & Savings Accounts
- Mobile Banking App
- Money Transfers
- Bill Payments
- Loans (Personal, Business, Mortgage)
- Fixed Deposits
- ATM Network
- Internet Banking

GUIDELINES:
- NEVER ask for passwords, PINs, or account numbers
- If you don't know something: "Call us at +256 312 310 000"
- You CANNOT perform transactions - guide users how to do them
- Reference conversation context naturally

CONVERSATION STYLE:
❌ "Go to transfers section"
✅ "I can help! 💰 Just tap 'Transfer' on your dashboard, enter recipient details, and you're done!"
"""


def get_conversation_history():
    """Get conversation history from session"""
    if 'ai_conversation' not in session:
        session['ai_conversation'] = []
    return session['ai_conversation']


def save_to_history(role, content):
    """Save message to session history"""
    if 'ai_conversation' not in session:
        session['ai_conversation'] = []
    
    session['ai_conversation'].append({
        'role': role,
        'content': content,
        'timestamp': datetime.now().isoformat()
    })
    
    # Keep last 20 messages
    if len(session['ai_conversation']) > 20:
        session['ai_conversation'] = session['ai_conversation'][-20:]
    
    session.modified = True


def build_prompt(user_message, history):
    """Build conversational prompt with context"""
    user_name = current_user.first_name if hasattr(current_user, 'first_name') else 'there'
    
    if history and len(history) > 0:
        recent = history[-6:]  # Last 3 exchanges
        conversation = "\n".join([
            f"{'Customer' if msg['role'] == 'user' else 'Alex'}: {msg['content']}"
            for msg in recent
        ])
        
        return f"""{BANKING_CONTEXT}

ONGOING CONVERSATION with {user_name}:
{conversation}

Customer: {user_message}

Alex (respond naturally):"""
    else:
        return f"""{BANKING_CONTEXT}

NEW CONVERSATION:
Customer: {user_name}
Message: {user_message}

Alex (greet warmly using their name):"""


@ai_assistant_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    """Handle chat messages - MAIN ENDPOINT"""
    logger.info(f"📥 Chat request received from {current_user.username}")
    
    # Check if model is initialized
    if model is None:
        if not init_gemini():
            logger.error("❌ Gemini model not available")
            return jsonify({
                'success': False,
                'error': 'AI Assistant is currently unavailable. Please call +256 312 310 000 for assistance.',
                'message': None
            }), 503
    
    try:
        # Get request data
        data = request.get_json()
        if not data:
            logger.error("❌ No JSON data received")
            return jsonify({
                'success': False,
                'error': 'Invalid request format'
            }), 400
        
        user_message = data.get('message', '').strip()
        
        if not user_message:
            return jsonify({
                'success': False,
                'error': 'Please enter a message'
            }), 400
        
        logger.info(f"💬 User message: {user_message[:50]}...")
        
        # Get history
        history = get_conversation_history()
        
        # Build prompt
        prompt = build_prompt(user_message, history)
        
        # Generate response
        try:
            response = model.generate_content(prompt)
            
            if not response or not response.text:
                raise Exception("Empty response from Gemini")
            
            assistant_message = response.text.strip()
            logger.info(f"✅ AI response: {assistant_message[:50]}...")
            
            # Save to history
            save_to_history('user', user_message)
            save_to_history('assistant', assistant_message)
            
            return jsonify({
                'success': True,
                'message': assistant_message,
                'error': None,
                'conversation_length': len(get_conversation_history())
            }), 200
            
        except Exception as e:
            error_str = str(e).lower()
            logger.error(f"❌ Gemini error: {e}")
            
            if 'quota' in error_str or '429' in error_str:
                error_msg = "I'm experiencing high demand right now. Please try again in a moment! 😊"
            elif 'api key' in error_str:
                error_msg = "AI configuration issue. Contact support at +256 312 310 000."
            else:
                error_msg = "I had a small hiccup. Could you try asking that again?"
            
            return jsonify({
                'success': False,
                'error': error_msg,
                'message': None
            }), 500
        
    except Exception as e:
        logger.error(f"❌ Chat error: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': 'Sorry, something went wrong. Please try again.',
            'message': None
        }), 500


@ai_assistant_bp.route('/suggestions', methods=['GET'])
@login_required
def get_suggestions():
    """Get contextual suggestions"""
    history = get_conversation_history()
    
    if not history or len(history) == 0:
        suggestions = [
            "👋 What services do you offer?",
            "💰 How do I open a savings account?",
            "📱 Tell me about mobile banking",
            "🏧 Where's the nearest ATM?"
        ]
    else:
        last_topic = history[-1]['content'].lower()
        
        if 'transfer' in last_topic:
            suggestions = [
                "What are the transfer limits?",
                "How long does it take?",
                "What fees apply?"
            ]
        elif 'account' in last_topic:
            suggestions = [
                "What documents do I need?",
                "What's the minimum balance?",
                "Can I open online?"
            ]
        else:
            suggestions = [
                "Tell me more",
                "What are the fees?",
                "How do I get started?"
            ]
    
    return jsonify({
        'success': True,
        'suggestions': suggestions
    }), 200


@ai_assistant_bp.route('/history', methods=['GET'])
@login_required
def get_history():
    """Get conversation history"""
    history = get_conversation_history()
    return jsonify({
        'success': True,
        'history': history,
        'count': len(history)
    }), 200


@ai_assistant_bp.route('/clear-history', methods=['POST'])
@login_required
def clear_history():
    """Clear conversation history"""
    session['ai_conversation'] = []
    session.modified = True
    
    return jsonify({
        'success': True,
        'message': 'Conversation cleared! 🎯'
    }), 200


@ai_assistant_bp.route('/status', methods=['GET'])
@login_required
def get_status():
    """Check AI status"""
    is_available = model is not None
    history = get_conversation_history()
    
    return jsonify({
        'success': True,
        'available': is_available,
        'model': 'gemini-1.5-flash' if is_available else None,
        'message': 'AI Assistant ready! 🤖' if is_available else 'AI not configured',
        'conversation_active': len(history) > 0,
        'message_count': len(history)
    }), 200


# Debug route to test blueprint registration
@ai_assistant_bp.route('/test', methods=['GET'])
def test():
    """Test endpoint to verify blueprint is registered"""
    return jsonify({
        'success': True,
        'message': 'AI Assistant blueprint is working!',
        'endpoint': '/ai-assistant/test'
    }), 200