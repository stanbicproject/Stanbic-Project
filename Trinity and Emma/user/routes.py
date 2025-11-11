"""
User routes: dashboard, transactions, payments, withdrawals, and account management.
Handles all user-facing banking operations.
"""

from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from user import user_bp
from user.forms import WithdrawalForm, PaymentForm, DepositForm, NewAccountForm, TransferForm
from models.user import User
from models.account import Account
from models.transaction import Transaction
from models.notification import Notification
from app import db
from datetime import datetime, timedelta
from sqlalchemy import func, desc

@user_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard with overview, statistics, and insights."""
    
    # Get user's accounts
    accounts = current_user.accounts.filter_by(is_active=True).all()
    
    # Calculate total balance
    total_balance = sum(account.balance for account in accounts)
    
    # Get recent transactions (last 10)
    recent_transactions = Transaction.query.join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.status == 'completed'
    ).order_by(Transaction.created_at.desc()).limit(10).all()
    
    # Get pending transactions
    pending_transactions = Transaction.query.join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.status == 'pending'
    ).order_by(Transaction.created_at.desc()).all()
    
    # Calculate monthly statistics
    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Total income this month
    monthly_income = db.session.query(func.sum(Transaction.amount)).join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.transaction_type.in_(['deposit', 'transfer_in']),
        Transaction.status == 'completed',
        Transaction.created_at >= start_of_month
    ).scalar() or 0
    
    # Total expenses this month
    monthly_expenses = db.session.query(func.sum(Transaction.amount)).join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.transaction_type.in_(['withdrawal', 'payment', 'transfer_out']),
        Transaction.status == 'completed',
        Transaction.created_at >= start_of_month
    ).scalar() or 0
    
    # Calculate spending by category (payment method)
    spending_by_category = db.session.query(
        Transaction.payment_method,
        func.sum(Transaction.amount)
    ).join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.transaction_type == 'payment',
        Transaction.status == 'completed',
        Transaction.created_at >= start_of_month
    ).group_by(Transaction.payment_method).all()
    
    # Get last 30 days transaction data for graph
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_transactions = db.session.query(
        func.date(Transaction.created_at).label('date'),
        func.sum(func.case(
            (Transaction.transaction_type.in_(['deposit', 'transfer_in']), Transaction.amount),
            else_=0
        )).label('income'),
        func.sum(func.case(
            (Transaction.transaction_type.in_(['withdrawal', 'payment', 'transfer_out']), Transaction.amount),
            else_=0
        )).label('expenses')
    ).join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.status == 'completed',
        Transaction.created_at >= thirty_days_ago
    ).group_by(func.date(Transaction.created_at)).all()
    
    # Financial insights and projections
    insights = generate_financial_insights(monthly_income, monthly_expenses, total_balance)
    
    # Get unread notifications count
    unread_notifications = current_user.get_unread_notifications_count()
    
    return render_template('dashboard.html',
                         accounts=accounts,
                         total_balance=total_balance,
                         recent_transactions=recent_transactions,
                         pending_transactions=pending_transactions,
                         monthly_income=monthly_income,
                         monthly_expenses=monthly_expenses,
                         spending_by_category=spending_by_category,
                         daily_transactions=daily_transactions,
                         insights=insights,
                         unread_notifications=unread_notifications)


def generate_financial_insights(income, expenses, balance):
    """Generate financial insights and projections."""
    insights = []
    
    # Savings rate
    if income > 0:
        savings_rate = ((income - expenses) / income) * 100
        if savings_rate > 20:
            insights.append({
                'type': 'success',
                'title': 'Excellent Savings Rate',
                'message': f"You're saving {savings_rate:.1f}% of your income. Keep up the great work!"
            })
        elif savings_rate > 0:
            insights.append({
                'type': 'info',
                'title': 'Good Savings',
                'message': f"You're saving {savings_rate:.1f}% of your income. Try to increase this to 20% or more."
            })
        else:
            insights.append({
                'type': 'warning',
                'title': 'Spending Alert',
                'message': "Your expenses exceed your income this month. Consider reviewing your spending."
            })
    
    # Balance projection
    if expenses > 0 and balance > 0:
        months_of_expenses = balance / expenses
        if months_of_expenses < 3:
            insights.append({
                'type': 'warning',
                'title': 'Emergency Fund',
                'message': f"Your balance covers {months_of_expenses:.1f} months of expenses. Aim for 3-6 months."
            })
        else:
            insights.append({
                'type': 'success',
                'title': 'Strong Emergency Fund',
                'message': f"Your balance covers {months_of_expenses:.1f} months of expenses. Well done!"
            })
    
    # Spending efficiency
    if income > 0:
        expense_ratio = (expenses / income) * 100
        if expense_ratio < 50:
            insights.append({
                'type': 'success',
                'title': 'Efficient Spending',
                'message': f"You're spending {expense_ratio:.1f}% of your income. This is very efficient!"
            })
        elif expense_ratio < 80:
            insights.append({
                'type': 'info',
                'title': 'Moderate Spending',
                'message': f"You're spending {expense_ratio:.1f}% of your income. Room for improvement."
            })
    
    return insights


@user_bp.route('/transactions')
@login_required
def transactions():
    """View all transactions with filtering."""
    
    # Get filter parameters
    account_id = request.args.get('account_id', type=int)
    transaction_type = request.args.get('type')
    status = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    
    # Build query
    query = Transaction.query.join(Account).filter(Account.user_id == current_user.id)
    
    if account_id:
        query = query.filter(Transaction.account_id == account_id)
    if transaction_type:
        query = query.filter(Transaction.transaction_type == transaction_type)
    if status:
        query = query.filter(Transaction.status == status)
    
    # Paginate results
    from config import Config
    transactions = query.order_by(Transaction.created_at.desc()).paginate(
        page=page, per_page=Config.TRANSACTIONS_PER_PAGE, error_out=False
    )
    
    # Get user's accounts for filter dropdown
    accounts = current_user.accounts.filter_by(is_active=True).all()
    
    return render_template('transactions.html',
                         transactions=transactions,
                         accounts=accounts,
                         selected_account=account_id,
                         selected_type=transaction_type,
                         selected_status=status)


@user_bp.route('/withdrawals', methods=['GET', 'POST'])
@login_required
def withdrawals():
    """Withdraw money from account."""
    
    form = WithdrawalForm()
    
    # Populate account choices
    active_accounts = current_user.accounts.filter_by(is_active=True).all()
    form.account_id.choices = [(a.id, f'{a.account_name} - UGX {a.available_balance:,.2f}') 
                                for a in active_accounts]
    
    if form.validate_on_submit():
        account = Account.query.get(form.account_id.data)
        
        if not account or account.user_id != current_user.id:
            flash('Invalid account selected.', 'danger')
            return redirect(url_for('user.withdrawals'))
        
        if not account.is_active:
            flash('This account is not active.', 'danger')
            return redirect(url_for('user.withdrawals'))
        
        if account.available_balance < form.amount.data:
            flash('Insufficient funds in the selected account.', 'danger')
            return redirect(url_for('user.withdrawals'))
        
        # Create withdrawal transaction
        transaction = Transaction(
            transaction_id=Transaction.generate_transaction_id(),
            transaction_type='withdrawal',
            amount=form.amount.data,
            description=form.description.data or 'Cash withdrawal',
            status='completed',  # In production, may be 'pending' for approval
            balance_before=account.balance,
            account_id=account.id
        )
        
        # Update account balance
        account.update_balance(form.amount.data, 'withdrawal')
        transaction.balance_after = account.balance
        transaction.complete_transaction()
        
        db.session.add(transaction)
        
        # Create notification
        notification = Notification.create_transaction_notification(
            current_user.id, 'withdrawal', form.amount.data, transaction.transaction_id
        )
        db.session.add(notification)
        
        db.session.commit()
        
        flash(f'Withdrawal of UGX {form.amount.data:,.2f} completed successfully!', 'success')
        return redirect(url_for('user.transactions'))
    
    # Get recent withdrawals
    recent_withdrawals = Transaction.query.join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.transaction_type == 'withdrawal'
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('withdrawals.html', form=form, recent_withdrawals=recent_withdrawals)


@user_bp.route('/payments', methods=['GET', 'POST'])
@login_required
def payments():
    """Make payments (transfers, mobile money, utilities)."""
    
    form = PaymentForm()
    
    # Populate account choices
    active_accounts = current_user.accounts.filter_by(is_active=True).all()
    form.account_id.choices = [(a.id, f'{a.account_name} - UGX {a.available_balance:,.2f}') 
                                for a in active_accounts]
    
    if form.validate_on_submit():
        account = Account.query.get(form.account_id.data)
        
        if not account or account.user_id != current_user.id:
            flash('Invalid account selected.', 'danger')
            return redirect(url_for('user.payments'))
        
        if not account.is_active:
            flash('This account is not active.', 'danger')
            return redirect(url_for('user.payments'))
        
        if account.available_balance < form.amount.data:
            flash('Insufficient funds in the selected account.', 'danger')
            return redirect(url_for('user.payments'))
        
        # Create payment transaction
        transaction = Transaction(
            transaction_id=Transaction.generate_transaction_id(),
            transaction_type='payment',
            amount=form.amount.data,
            description=form.description.data or f'Payment to {form.payee_name.data}',
            payee_name=form.payee_name.data,
            payee_account=form.payee_account.data,
            payment_method=form.payment_method.data,
            reference_number=form.reference.data,
            status='completed',  # In production, may be 'pending'
            balance_before=account.balance,
            account_id=account.id
        )
        
        # Update account balance
        account.update_balance(form.amount.data, 'payment')
        transaction.balance_after = account.balance
        transaction.complete_transaction()
        
        db.session.add(transaction)
        
        # Create notification
        notification = Notification.create_transaction_notification(
            current_user.id, 'payment', form.amount.data, transaction.transaction_id
        )
        db.session.add(notification)
        
        db.session.commit()
        
        flash(f'Payment of UGX {form.amount.data:,.2f} to {form.payee_name.data} completed successfully!', 'success')
        return redirect(url_for('user.transactions'))
    
    # Get recent payments
    recent_payments = Transaction.query.join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.transaction_type == 'payment'
    ).order_by(Transaction.created_at.desc()).limit(5).all()
    
    return render_template('payments.html', form=form, recent_payments=recent_payments)


@user_bp.route('/balance')
@login_required
def balance():
    """View account balances and details."""
    
    accounts = current_user.accounts.filter_by(is_active=True).all()
    total_balance = sum(account.balance for account in accounts)
    
    # Get account summaries
    account_summaries = []
    for account in accounts:
        summary = account.get_monthly_summary()
        account_summaries.append({
            'account': account,
            'summary': summary
        })
    
    return render_template('balance.html',
                         accounts=accounts,
                         total_balance=total_balance,
                         account_summaries=account_summaries)


@user_bp.route('/accounts', methods=['GET', 'POST'])
@login_required
def accounts():
    """View and manage accounts."""
    
    form = NewAccountForm()
    
    if form.validate_on_submit():
        # Create new account (pending approval)
        account = Account(
            account_number=Account.generate_account_number(),
            account_type=form.account_type.data,
            account_name=form.account_name.data,
            user_id=current_user.id,
            is_active=False  # Requires admin approval
        )
        
        db.session.add(account)
        
        # Create notification
        notification = Notification(
            user_id=current_user.id,
            title='New Account Request Submitted',
            message=f'Your request for a {form.account_type.data} account has been submitted for approval.',
            notification_type='account',
            priority='normal'
        )
        db.session.add(notification)
        
        db.session.commit()
        
        flash('Account request submitted successfully! It will be reviewed by our team.', 'success')
        return redirect(url_for('user.accounts'))
    
    # Get all user accounts (active and pending)
    user_accounts = current_user.accounts.all()
    
    return render_template('accounts.html', form=form, accounts=user_accounts)


@user_bp.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    """Transfer money between own accounts."""
    
    form = TransferForm()
    
    # Populate account choices
    active_accounts = current_user.accounts.filter_by(is_active=True).all()
    form.from_account_id.choices = [(a.id, f'{a.account_name} - UGX {a.available_balance:,.2f}') 
                                     for a in active_accounts]
    form.to_account_id.choices = [(a.id, f'{a.account_name}') for a in active_accounts]
    
    if form.validate_on_submit():
        if form.from_account_id.data == form.to_account_id.data:
            flash('Cannot transfer to the same account.', 'danger')
            return redirect(url_for('user.transfer'))
        
        from_account = Account.query.get(form.from_account_id.data)
        to_account = Account.query.get(form.to_account_id.data)
        
        if not from_account or not to_account:
            flash('Invalid accounts selected.', 'danger')
            return redirect(url_for('user.transfer'))
        
        if from_account.user_id != current_user.id or to_account.user_id != current_user.id:
            flash('You can only transfer between your own accounts.', 'danger')
            return redirect(url_for('user.transfer'))
        
        if from_account.available_balance < form.amount.data:
            flash('Insufficient funds in the source account.', 'danger')
            return redirect(url_for('user.transfer'))
        
        # Create transfer out transaction
        transfer_out = Transaction(
            transaction_id=Transaction.generate_transaction_id(),
            transaction_type='transfer_out',
            amount=form.amount.data,
            description=form.description.data or f'Transfer to {to_account.account_name}',
            status='completed',
            balance_before=from_account.balance,
            account_id=from_account.id
        )
        
        from_account.update_balance(form.amount.data, 'transfer_out')
        transfer_out.balance_after = from_account.balance
        transfer_out.complete_transaction()
        
        # Create transfer in transaction
        transfer_in = Transaction(
            transaction_id=Transaction.generate_transaction_id(),
            transaction_type='transfer_in',
            amount=form.amount.data,
            description=form.description.data or f'Transfer from {from_account.account_name}',
            status='completed',
            balance_before=to_account.balance,
            account_id=to_account.id
        )
        
        to_account.update_balance(form.amount.data, 'transfer_in')
        transfer_in.balance_after = to_account.balance
        transfer_in.complete_transaction()
        
        db.session.add_all([transfer_out, transfer_in])
        db.session.commit()
        
        flash(f'Transfer of UGX {form.amount.data:,.2f} completed successfully!', 'success')
        return redirect(url_for('user.transactions'))
    
    return render_template('transfer.html', form=form)


@user_bp.route('/notifications')
@login_required
def notifications():
    """View all notifications."""
    
    page = request.args.get('page', 1, type=int)
    
    notifications = current_user.notifications.order_by(
        Notification.created_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    
    return render_template('notifications.html', notifications=notifications)


@user_bp.route('/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read."""
    
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    notification.mark_as_read()
    db.session.commit()
    
    return jsonify({'success': True})


@user_bp.route('/api/dashboard-data')
@login_required
def dashboard_data():
    """API endpoint for dashboard chart data."""
    
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    daily_data = db.session.query(
        func.date(Transaction.created_at).label('date'),
        func.sum(func.case(
            (Transaction.transaction_type.in_(['deposit', 'transfer_in']), Transaction.amount),
            else_=0
        )).label('income'),
        func.sum(func.case(
            (Transaction.transaction_type.in_(['withdrawal', 'payment', 'transfer_out']), Transaction.amount),
            else_=0
        )).label('expenses')
    ).join(Account).filter(
        Account.user_id == current_user.id,
        Transaction.status == 'completed',
        Transaction.created_at >= start_date
    ).group_by(func.date(Transaction.created_at)).all()
    
    return jsonify({
        'labels': [str(d.date) for d in daily_data],
        'income': [float(d.income) for d in daily_data],
        'expenses': [float(d.expenses) for d in daily_data]
    })