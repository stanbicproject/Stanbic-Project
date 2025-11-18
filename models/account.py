"""
Account model for managing bank accounts.
Each user can have multiple accounts (savings, current, etc.).
"""
from extensions import db  # ✅ CORRECT - Change this line!
from datetime import datetime
import random
import string

class Account(db.Model):
    """Bank account model."""
    
    __tablename__ = 'accounts'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Account details
    account_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    account_type = db.Column(db.String(20), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    
    # Balance
    balance = db.Column(db.Float, default=0.0, nullable=False)
    available_balance = db.Column(db.Float, default=0.0, nullable=False)
    
    # Currency
    currency = db.Column(db.String(3), default='UGX', nullable=False)
    
    # Status
    is_active = db.Column(db.Boolean, default=False)
    is_default = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relationships
    transactions = db.relationship('Transaction', backref='account', lazy='dynamic', cascade='all, delete-orphan')
    
    @staticmethod
    def generate_account_number():
        """Generate unique 16-digit account number."""
        while True:
            account_number = '9030' + ''.join(random.choices(string.digits, k=12))
            if not Account.query.filter_by(account_number=account_number).first():
                return account_number
    
    def update_balance(self, amount, transaction_type):
        """Update account balance based on transaction type."""
        if transaction_type in ['deposit', 'transfer_in']:
            self.balance += amount
            self.available_balance += amount
        elif transaction_type in ['withdrawal', 'payment', 'transfer_out']:
            if self.available_balance >= amount:
                self.balance -= amount
                self.available_balance -= amount
                return True
            return False
        return True
    
    def get_recent_transactions(self, limit=10):
        """Get recent transactions for this account."""
        # Import here to avoid circular imports
        from models.transaction import Transaction
        return self.transactions.order_by(Transaction.created_at.desc()).limit(limit).all()
    
    def get_monthly_summary(self):
        """Get current month's transaction summary."""
        from datetime import timedelta
        from sqlalchemy import func
        # Import Transaction model here to avoid circular imports
        from models.transaction import Transaction
        
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        deposits = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.account_id == self.id,
            Transaction.transaction_type.in_(['deposit', 'transfer_in']),
            Transaction.created_at >= start_of_month,
            Transaction.status == 'completed'
        ).scalar() or 0
        
        withdrawals = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.account_id == self.id,
            Transaction.transaction_type.in_(['withdrawal', 'payment', 'transfer_out']),
            Transaction.created_at >= start_of_month,
            Transaction.status == 'completed'
        ).scalar() or 0
        
        return {
            'deposits': deposits,
            'withdrawals': withdrawals,
            'net': deposits - withdrawals
        }
    
    def __repr__(self):
        return f'<Account {self.account_number}>'