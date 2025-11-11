"""
User forms for transactions, payments, and account management.
"""

from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, NumberRange, Length, Optional, ValidationError
from config import Config

class WithdrawalForm(FlaskForm):
    """Form for withdrawing money."""
    
    account_id = SelectField('From Account', coerce=int, validators=[
        DataRequired(message='Please select an account')
    ])
    
    amount = FloatField('Amount (UGX)', validators=[
        DataRequired(message='Amount is required'),
        NumberRange(min=Config.MIN_TRANSACTION_AMOUNT, message=f'Minimum withdrawal is UGX {Config.MIN_TRANSACTION_AMOUNT:,.2f}')
    ])
    
    description = TextAreaField('Description (Optional)', validators=[
        Length(max=200, message='Description must be less than 200 characters')
    ])
    
    def validate_amount(self, amount):
        """Validate withdrawal amount against daily limit."""
        if amount.data > Config.DAILY_WITHDRAWAL_LIMIT:
            raise ValidationError(f'Daily withdrawal limit is UGX {Config.DAILY_WITHDRAWAL_LIMIT:,.2f}')


class PaymentForm(FlaskForm):
    """Form for making payments."""
    
    account_id = SelectField('From Account', coerce=int, validators=[
        DataRequired(message='Please select an account')
    ])
    
    payment_method = SelectField('Payment Method', choices=[
        ('bank_transfer', 'Bank Transfer'),
        ('mobile_money', 'Mobile Money'),
        ('utility', 'Utility Bill'),
        ('airtime', 'Airtime Top-up')
    ], validators=[DataRequired(message='Please select a payment method')])
    
    payee_name = StringField('Payee Name', validators=[
        DataRequired(message='Payee name is required'),
        Length(min=2, max=100, message='Payee name must be between 2 and 100 characters')
    ])
    
    payee_account = StringField('Payee Account/Phone Number', validators=[
        DataRequired(message='Payee account is required'),
        Length(min=5, max=50)
    ])
    
    amount = FloatField('Amount (UGX)', validators=[
        DataRequired(message='Amount is required'),
        NumberRange(min=Config.MIN_TRANSACTION_AMOUNT, message=f'Minimum payment is UGX {Config.MIN_TRANSACTION_AMOUNT:,.2f}')
    ])
    
    reference = StringField('Reference (Optional)', validators=[
        Length(max=50, message='Reference must be less than 50 characters')
    ])
    
    description = TextAreaField('Description (Optional)', validators=[
        Length(max=200, message='Description must be less than 200 characters')
    ])
    
    def validate_amount(self, amount):
        """Validate payment amount against daily limit."""
        if amount.data > Config.DAILY_PAYMENT_LIMIT:
            raise ValidationError(f'Daily payment limit is UGX {Config.DAILY_PAYMENT_LIMIT:,.2f}')


class DepositForm(FlaskForm):
    """Form for depositing money (typically done by admin/teller)."""
    
    account_id = SelectField('To Account', coerce=int, validators=[
        DataRequired(message='Please select an account')
    ])
    
    amount = FloatField('Amount (UGX)', validators=[
        DataRequired(message='Amount is required'),
        NumberRange(min=Config.MIN_TRANSACTION_AMOUNT, message=f'Minimum deposit is UGX {Config.MIN_TRANSACTION_AMOUNT:,.2f}')
    ])
    
    description = TextAreaField('Description (Optional)', validators=[
        Length(max=200, message='Description must be less than 200 characters')
    ])


class NewAccountForm(FlaskForm):
    """Form for opening a new account."""
    
    account_type = SelectField('Account Type', choices=[
        ('savings', 'Savings Account'),
        ('current', 'Current Account'),
        ('fixed_deposit', 'Fixed Deposit')
    ], validators=[DataRequired(message='Please select an account type')])
    
    account_name = StringField('Account Name', validators=[
        DataRequired(message='Account name is required'),
        Length(min=5, max=100, message='Account name must be between 5 and 100 characters')
    ])
    
    initial_deposit = FloatField('Initial Deposit (Optional)', validators=[
        Optional(),
        NumberRange(min=0, message='Initial deposit cannot be negative')
    ])


class TransferForm(FlaskForm):
    """Form for transferring between own accounts."""
    
    from_account_id = SelectField('From Account', coerce=int, validators=[
        DataRequired(message='Please select source account')
    ])
    
    to_account_id = SelectField('To Account', coerce=int, validators=[
        DataRequired(message='Please select destination account')
    ])
    
    amount = FloatField('Amount (UGX)', validators=[
        DataRequired(message='Amount is required'),
        NumberRange(min=Config.MIN_TRANSACTION_AMOUNT, message=f'Minimum transfer is UGX {Config.MIN_TRANSACTION_AMOUNT:,.2f}')
    ])
    
    description = TextAreaField('Description (Optional)', validators=[
        Length(max=200, message='Description must be less than 200 characters')
    ])