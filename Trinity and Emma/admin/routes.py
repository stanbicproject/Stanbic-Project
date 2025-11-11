"""
Admin routes: user management, account approval, transaction monitoring.
Only accessible to admin users.
"""

from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from functools import wraps
from admin import admin_bp
from models.user import User
from models.account import Account
from models.transaction import Transaction
from models.notification import Notification
from app import db
from datetime import datetime, timedelta
from sqlalchemy import func

def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You must be an administrator to access this page.', 'danger')
            return redirect(url_for('user.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard with system overview."""
    
    # Get statistics
    total_users = User.query.filter_by(is_admin=False).count()
    active_users = User.query.filter_by(is_admin=False, is_active=True, is_verified=True).count()
    pending_verifications = User.query.filter_by(is_verified=False).count()
    
    total_accounts = Account.query.count()
    active_accounts = Account.query.filter_by(is_active=True).count()
    pending_accounts = Account.query.filter_by(is_active=False).count()
    
    # Calculate total deposits
    total_deposits = db.session.query(func.sum(Account.balance)).scalar() or 0
    
    # Transaction statistics
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    transactions_today = Transaction.query.filter(
        Transaction.created_at >= today
    ).count()
    
    pending_transactions = Transaction.query.filter_by(status='pending').count()
    
    # Recent activity
    recent_users = User.query.filter_by(is_admin=False).order_by(
        User.created_at.desc()
    ).limit(10).all()
    
    recent_transactions = Transaction.query.order_by(
        Transaction.created_at.desc()
    ).limit(15).all()
    
    pending_account_requests = Account.query.filter_by(is_active=False).order_by(
        Account.created_at.desc()
    ).all()
    
    # Monthly transaction volume
    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_volume = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.status == 'completed',
        Transaction.created_at >= start_of_month
    ).scalar() or 0
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         active_users=active_users,
                         pending_verifications=pending_verifications,
                         total_accounts=total_accounts,
                         active_accounts=active_accounts,
                         pending_accounts=pending_accounts,
                         total_deposits=total_deposits,
                         transactions_today=transactions_today,
                         pending_transactions=pending_transactions,
                         recent_users=recent_users,
                         recent_transactions=recent_transactions,
                         pending_account_requests=pending_account_requests,
                         monthly_volume=monthly_volume)


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """View and manage all users."""
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    
    query = User.query.filter_by(is_admin=False)
    
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            (User.email.like(search_term)) |
            (User.username.like(search_term)) |
            (User.first_name.like(search_term)) |
            (User.last_name.like(search_term))
        )
    
    from config import Config
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=Config.USERS_PER_PAGE, error_out=False
    )
    
    return render_template('admin_users.html', users=users, search=search)


@admin_bp.route('/users/<int:user_id>')
@login_required
@admin_required
def user_detail(user_id):
    """View detailed user information."""
    
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('Cannot view admin user details.', 'warning')
        return redirect(url_for('admin.users'))
    
    # Get user's accounts and transactions
    accounts = user.accounts.all()
    recent_transactions = Transaction.query.join(Account).filter(
        Account.user_id == user.id
    ).order_by(Transaction.created_at.desc()).limit(20).all()
    
    return render_template('admin_user_detail.html',
                         user=user,
                         accounts=accounts,
                         recent_transactions=recent_transactions)


@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    """Activate or deactivate a user."""
    
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        return jsonify({'success': False, 'message': 'Cannot modify admin user'}), 403
    
    user.is_active = not user.is_active
    
    # Create notification for user
    status = 'activated' if user.is_active else 'deactivated'
    notification = Notification(
        user_id=user.id,
        title=f'Account {status.title()}',
        message=f'Your account has been {status} by an administrator.',
        notification_type='account',
        priority='high'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    flash(f'User {user.username} has been {status}.', 'success')
    return jsonify({'success': True, 'is_active': user.is_active})


@admin_bp.route('/accounts/pending')
@login_required
@admin_required
def pending_accounts():
    """View pending account approval requests."""
    
    accounts = Account.query.filter_by(is_active=False).order_by(
        Account.created_at.desc()
    ).all()
    
    return render_template('admin_pending_accounts.html', accounts=accounts)


@admin_bp.route('/accounts/<int:account_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_account(account_id):
    """Approve a pending account."""
    
    account = Account.query.get_or_404(account_id)
    
    if account.is_active:
        return jsonify({'success': False, 'message': 'Account already approved'}), 400
    
    account.is_active = True
    account.approved_at = datetime.utcnow()
    
    # Create notification for user
    notification = Notification(
        user_id=account.user_id,
        title='Account Approved',
        message=f'Your {account.account_type} account ({account.account_number}) has been approved and is now active.',
        notification_type='account',
        priority='high'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    flash(f'Account {account.account_number} approved successfully.', 'success')
    return jsonify({'success': True})


@admin_bp.route('/accounts/<int:account_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_account(account_id):
    """Reject a pending account."""
    
    account = Account.query.get_or_404(account_id)
    
    # Create notification for user
    notification = Notification(
        user_id=account.user_id,
        title='Account Request Rejected',
        message=f'Your {account.account_type} account request has been rejected. Please contact support for more information.',
        notification_type='account',
        priority='high'
    )
    db.session.add(notification)
    
    # Delete the account
    db.session.delete(account)
    db.session.commit()
    
    flash(f'Account request rejected and removed.', 'success')
    return jsonify({'success': True})


@admin_bp.route('/transactions')
@login_required
@admin_required
def transactions():
    """View all transactions."""
    
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status')
    transaction_type = request.args.get('type')
    
    query = Transaction.query
    
    if status:
        query = query.filter_by(status=status)
    if transaction_type:
        query = query.filter_by(transaction_type=transaction_type)
    
    transactions = query.order_by(Transaction.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('admin_transactions.html',
                         transactions=transactions,
                         selected_status=status,
                         selected_type=transaction_type)


@admin_bp.route('/transactions/<int:transaction_id>')
@login_required
@admin_required
def transaction_detail(transaction_id):
    """View transaction details."""
    transaction = Transaction.query.get_or_404(transaction_id)
    account = transaction.account
    user = account.owner
    
    return render_template('admin_transaction_detail.html',
                         transaction=transaction,
                         account=account,
                         user=user)


@admin_bp.route('/deposit', methods=['GET', 'POST'])
@login_required
@admin_required
def make_deposit():
    """Admin can deposit money to user accounts."""
    
    from user.forms import DepositForm
    form = DepositForm()
    
    # Get all active accounts for dropdown
    all_accounts = Account.query.filter_by(is_active=True).all()
    form.account_id.choices = [
        (a.id, f'{a.account_number} - {a.owner.username} - {a.account_name}') 
        for a in all_accounts
    ]
    
    if form.validate_on_submit():
        account = Account.query.get(form.account_id.data)
        
        if not account:
            flash('Invalid account selected.', 'danger')
            return redirect(url_for('admin.make_deposit'))
        
        # Create deposit transaction
        transaction = Transaction(
            transaction_id=Transaction.generate_transaction_id(),
            transaction_type='deposit',
            amount=form.amount.data,
            description=form.description.data or 'Admin deposit',
            status='completed',
            balance_before=account.balance,
            account_id=account.id
        )
        
        # Update account balance
        account.update_balance(form.amount.data, 'deposit')
        transaction.balance_after = account.balance
        transaction.complete_transaction()
        
        db.session.add(transaction)
        
        # Create notification for user
        notification = Notification.create_transaction_notification(
            account.user_id, 'deposit', form.amount.data, transaction.transaction_id
        )
        db.session.add(notification)
        
        db.session.commit()
        
        flash(f'Deposit of UGX {form.amount.data:,.2f} to account {account.account_number} completed.', 'success')
        return redirect(url_for('admin.transactions'))
    
    return render_template('admin_deposit.html', form=form)


@admin_bp.route('/notifications/broadcast', methods=['GET', 'POST'])
@login_required
@admin_required
def broadcast_notification():
    """Send notification to all users."""
    
    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')
        priority = request.form.get('priority', 'normal')
        
        if not title or not message:
            flash('Title and message are required.', 'danger')
            return redirect(url_for('admin.broadcast_notification'))
        
        # Get all non-admin users
        users = User.query.filter_by(is_admin=False, is_active=True).all()
        
        # Create notification for each user
        notifications = []
        for user in users:
            notification = Notification(
                user_id=user.id,
                title=title,
                message=message,
                notification_type='system',
                priority=priority
            )
            notifications.append(notification)
        
        db.session.add_all(notifications)
        db.session.commit()
        
        flash(f'Notification sent to {len(users)} users.', 'success')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('admin_broadcast.html')


@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    """Generate system reports."""
    
    # Date range
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Transaction summary
    transaction_summary = db.session.query(
        Transaction.transaction_type,
        func.count(Transaction.id).label('count'),
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.status == 'completed',
        Transaction.created_at >= start_date
    ).group_by(Transaction.transaction_type).all()
    
    # Daily transaction volume
    daily_volume = db.session.query(
        func.date(Transaction.created_at).label('date'),
        func.count(Transaction.id).label('count'),
        func.sum(Transaction.amount).label('total')
    ).filter(
        Transaction.status == 'completed',
        Transaction.created_at >= start_date
    ).group_by(func.date(Transaction.created_at)).all()
    
    # Top users by transaction count
    top_users = db.session.query(
        User.id,
        User.username,
        User.first_name,
        User.last_name,
        func.count(Transaction.id).label('transaction_count'),
        func.sum(Transaction.amount).label('total_amount')
    ).join(Account).join(Transaction).filter(
        Transaction.status == 'completed',
        Transaction.created_at >= start_date
    ).group_by(User.id).order_by(desc('transaction_count')).limit(10).all()
    
    return render_template('admin_reports.html',
                         transaction_summary=transaction_summary,
                         daily_volume=daily_volume,
                         top_users=top_users,
                         days=days)


@admin_bp.route('/api/stats')
@login_required
@admin_required
def api_stats():
    """API endpoint for real-time statistics."""
    
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    stats = {
        'total_users': User.query.filter_by(is_admin=False).count(),
        'active_accounts': Account.query.filter_by(is_active=True).count(),
        'transactions_today': Transaction.query.filter(Transaction.created_at >= today).count(),
        'pending_accounts': Account.query.filter_by(is_active=False).count(),
        'total_deposits': float(db.session.query(func.sum(Account.balance)).scalar() or 0)
    }
    
    return jsonify(stats)