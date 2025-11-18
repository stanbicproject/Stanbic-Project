"""
Transaction model for recording all financial transactions.
Supports deposits, withdrawals, payments, and transfers.
"""

from extensions import db  # ✅ CORRECT - Change this line!
from datetime import datetime
import secrets

class Transaction(db.Model):
    """Transaction model for all banking operations."""
    
    __tablename__ = 'transactions'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Transaction details
    transaction_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    transaction_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='UGX')
    
    # Description and reference
    description = db.Column(db.String(200), nullable=True)
    reference_number = db.Column(db.String(50), nullable=True)
    
    # Payment details
    payee_name = db.Column(db.String(100), nullable=True)
    payee_account = db.Column(db.String(50), nullable=True)
    payment_method = db.Column(db.String(50), nullable=True)
    
    # Status and balances
    status = db.Column(db.String(20), default='pending')
    balance_before = db.Column(db.Float, nullable=True)
    balance_after = db.Column(db.Float, nullable=True)
    
    # Offline sync
    is_synced = db.Column(db.Boolean, default=True)
    created_offline = db.Column(db.Boolean, default=False)
    synced_at = db.Column(db.DateTime, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Foreign key
    account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'), nullable=False)
    
    @staticmethod
    def generate_transaction_id():
        """Generate unique transaction ID."""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_part = secrets.token_hex(4).upper()
        return f'TXN{timestamp}{random_part}'
    
    def complete_transaction(self):
        """Mark transaction as completed."""
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
        if self.created_offline:
            self.is_synced = True
            self.synced_at = datetime.utcnow()
    
    def fail_transaction(self, reason=None):
        """Mark transaction as failed."""
        self.status = 'failed'
        if reason:
            self.description = f"{self.description or ''} [Failed: {reason}]"
    
    def get_formatted_amount(self):
        """Return formatted amount with currency."""
        return f"{self.currency} {self.amount:,.2f}"
    
    def __repr__(self):
        return f'<Transaction {self.transaction_id}>'