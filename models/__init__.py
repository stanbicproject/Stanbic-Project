from extensions import db  # ✅ CORRECT

from models.user import User
from models.account import Account
from models.transaction import Transaction
from models.notification import Notification

__all__ = ['db', 'User', 'Account', 'Transaction', 'Notification']