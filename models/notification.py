"""
Notification model for user alerts and messages.
Tracks withdrawals, payments, account updates, and system messages.
"""

from extensions import db  # ✅ CORRECT - Change this line!
from datetime import datetime

class Notification(db.Model):
    """Notification model for user alerts."""
    
    __tablename__ = 'notifications'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Notification details
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(20), nullable=False)
    priority = db.Column(db.String(10), default='normal')
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    
    # Related transaction
    transaction_id = db.Column(db.String(50), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    
    # Foreign key
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def mark_as_read(self):
        """Mark notification as read."""
        if not self.is_read:
            self.is_read = True
            self.read_at = datetime.utcnow()
    
    @staticmethod
    def create_transaction_notification(user_id, transaction_type, amount, transaction_id):
        """Create notification for a transaction."""
        type_messages = {
            'deposit': f'Deposit of UGX {amount:,.2f} completed successfully',
            'withdrawal': f'Withdrawal of UGX {amount:,.2f} processed',
            'payment': f'Payment of UGX {amount:,.2f} sent successfully',
            'transfer_in': f'You received UGX {amount:,.2f}',
            'transfer_out': f'Transfer of UGX {amount:,.2f} sent'
        }
        
        notification = Notification(
            user_id=user_id,
            title=f'{transaction_type.replace("_", " ").title()} Alert',
            message=type_messages.get(transaction_type, f'Transaction of UGX {amount:,.2f}'),
            notification_type='transaction',
            transaction_id=transaction_id
        )
        
        return notification
    
    def __repr__(self):
        return f'<Notification {self.id}: {self.title}>'