"""
Quick payments routes for utilities, airtime, and bill payments.
Handles payments to various service providers in Uganda.
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from models import db
from models.account import Account
from models.transaction import Transaction
from models.notification import Notification
from datetime import datetime

quick_payments_bp = Blueprint('quick_payments', __name__, url_prefix='/quick-payments')

# Provider configurations
PROVIDERS = {
    'mtn_airtime': {
        'name': 'MTN Airtime',
        'icon': 'fas fa-phone',
        'category': 'airtime',
        'min_amount': 500,
        'max_amount': 500000
    },
    'mtn_data': {
        'name': 'MTN Data Bundle',
        'icon': 'fas fa-wifi',
        'category': 'data',
        'min_amount': 1000,
        'max_amount': 500000
    },
    'airtel_airtime': {
        'name': 'Airtel Airtime',
        'icon': 'fas fa-phone',
        'category': 'airtime',
        'min_amount': 500,
        'max_amount': 500000
    },
    'airtel_data': {
        'name': 'Airtel Data Bundle',
        'icon': 'fas fa-wifi',
        'category': 'data',
        'min_amount': 1000,
        'max_amount': 500000
    },
    'umeme': {
        'name': 'UMEME Electricity',
        'icon': 'fas fa-bolt',
        'category': 'utility',
        'min_amount': 1000,
        'max_amount': 5000000
    },
    'nwsc': {
        'name': 'NWSC Water Bill',
        'icon': 'fas fa-tint',
        'category': 'utility',
        'min_amount': 1000,
        'max_amount': 5000000
    },
    'dstv': {
        'name': 'DSTV Subscription',
        'icon': 'fas fa-tv',
        'category': 'tv',
        'min_amount': 10000,
        'max_amount': 500000
    },
    'gotv': {
        'name': 'GOtv Subscription',
        'icon': 'fas fa-tv',
        'category': 'tv',
        'min_amount': 5000,
        'max_amount': 100000
    },
    'startimes': {
        'name': 'StarTimes Subscription',
        'icon': 'fas fa-satellite-dish',
        'category': 'tv',
        'min_amount': 5000,
        'max_amount': 200000
    },
    'ura': {
        'name': 'URA Tax Payment',
        'icon': 'fas fa-landmark',
        'category': 'tax',
        'min_amount': 10000,
        'max_amount': 100000000
    },
    'nssf': {
        'name': 'NSSF Contribution',
        'icon': 'fas fa-piggy-bank',
        'category': 'savings',
        'min_amount': 10000,
        'max_amount': 10000000
    },
    'school_fees': {
        'name': 'School Fees Payment',
        'icon': 'fas fa-graduation-cap',
        'category': 'education',
        'min_amount': 10000,
        'max_amount': 50000000
    },
    'internet': {
        'name': 'Internet Bill Payment',
        'icon': 'fas fa-globe',
        'category': 'utility',
        'min_amount': 10000,
        'max_amount': 1000000
    }
}


@quick_payments_bp.route('/')
@login_required
def index():
    """Quick payments page."""
    # Get user's active accounts
    user_accounts = current_user.accounts.filter_by(is_active=True).all()
    
    # Get recent quick payments
    recent_quick_payments = Transaction.query.join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.transaction_type == 'payment',
        Transaction.payment_method == 'quick_payment'
    ).order_by(Transaction.created_at.desc()).limit(10).all()
    
    # Add provider info to transactions
    for payment in recent_quick_payments:
        provider_key = payment.payee_name.lower().replace(' ', '_').replace('subscription', '').replace('payment', '').replace('bill', '').strip()
        if provider_key in PROVIDERS:
            payment.icon = PROVIDERS[provider_key]['icon']
        else:
            payment.icon = 'fas fa-credit-card'
    
    return render_template('quick_payments.html',
                         user_accounts=user_accounts,
                         recent_quick_payments=recent_quick_payments)


@quick_payments_bp.route('/process', methods=['POST'])
@login_required
def process_payment():
    """Process quick payment."""
    try:
        data = request.get_json()
        
        # Validate data
        provider_key = data.get('provider')
        account_id = data.get('account_id')
        reference_number = data.get('reference_number')
        amount = float(data.get('amount', 0))
        description = data.get('description', '')
        
        if not all([provider_key, account_id, reference_number, amount]):
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
        
        # Validate provider
        if provider_key not in PROVIDERS:
            return jsonify({
                'success': False,
                'message': 'Invalid provider'
            }), 400
        
        provider = PROVIDERS[provider_key]
        
        # Validate amount
        if amount < provider['min_amount']:
            return jsonify({
                'success': False,
                'message': f"Minimum amount is UGX {provider['min_amount']:,.2f}"
            }), 400
        
        if amount > provider['max_amount']:
            return jsonify({
                'success': False,
                'message': f"Maximum amount is UGX {provider['max_amount']:,.2f}"
            }), 400
        
        # Get account
        account = Account.query.get(account_id)
        if not account or account.user_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'Invalid account'
            }), 400
        
        if not account.is_active:
            return jsonify({
                'success': False,
                'message': 'Account is not active'
            }), 400
        
        # Check balance
        if account.available_balance < amount:
            return jsonify({
                'success': False,
                'message': 'Insufficient funds'
            }), 400
        
        # Create transaction
        transaction = Transaction(
            transaction_id=Transaction.generate_transaction_id(),
            transaction_type='payment',
            amount=amount,
            description=description or f'{provider["name"]} - {reference_number}',
            payee_name=provider['name'],
            payee_account=reference_number,
            payment_method='quick_payment',
            reference_number=reference_number,
            status='completed',
            balance_before=account.balance,
            account_id=account.id
        )
        
        # Update account balance
        success = account.update_balance(amount, 'payment')
        if not success:
            return jsonify({
                'success': False,
                'message': 'Failed to update balance'
            }), 500
        
        transaction.balance_after = account.balance
        transaction.complete_transaction()
        
        db.session.add(transaction)
        
        # Create notification
        notification = Notification.create_transaction_notification(
            current_user.id,
            'payment',
            amount,
            transaction.transaction_id
        )
        notification.title = f'{provider["name"]} Payment'
        notification.message = f'Payment of UGX {amount:,.2f} to {provider["name"]} ({reference_number}) completed successfully.'
        
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Payment completed successfully',
            'provider_name': provider['name'],
            'amount': amount,
            'transaction_id': transaction.transaction_id,
            'reference': reference_number
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'message': 'Invalid amount'
        }), 400
    except Exception as e:
        db.session.rollback()
        print(f"Quick payment error: {e}")
        return jsonify({
            'success': False,
            'message': 'An error occurred while processing payment'
        }), 500


@quick_payments_bp.route('/providers')
@login_required
def get_providers():
    """Get list of available providers."""
    return jsonify({
        'success': True,
        'providers': PROVIDERS
    })


@quick_payments_bp.route('/validate-reference', methods=['POST'])
@login_required
def validate_reference():
    """
    Validate reference number for a provider.
    In production, this would check with the actual provider API.
    """
    try:
        data = request.get_json()
        provider_key = data.get('provider')
        reference_number = data.get('reference_number')
        
        if not provider_key or not reference_number:
            return jsonify({
                'success': False,
                'message': 'Missing required fields'
            }), 400
        
        if provider_key not in PROVIDERS:
            return jsonify({
                'success': False,
                'message': 'Invalid provider'
            }), 400
        
        # In production, validate with provider API
        # For now, basic validation
        if len(reference_number) < 5:
            return jsonify({
                'success': False,
                'message': 'Invalid reference number'
            }), 400
        
        # Mock customer info (in production, fetch from provider)
        customer_info = {
            'name': 'Customer Name',
            'account_status': 'Active',
            'reference': reference_number
        }
        
        return jsonify({
            'success': True,
            'valid': True,
            'customer_info': customer_info
        })
        
    except Exception as e:
        print(f"Reference validation error: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to validate reference'
        }), 500