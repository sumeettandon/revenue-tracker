import os
import enum
import io
from datetime import date

import pandas as pd
from dotenv import load_dotenv
import click # Keep click here as it's used for CLI commands
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from sqlalchemy import func, extract
from werkzeug.security import generate_password_hash, check_password_hash

# --- App Configuration ---

app = Flask(__name__)
# Specifies the path to the database file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance/tracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppresses a warning

# Load environment variables from .env file
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY', 'a_very_secret_key_default') # Necessary for sessions and flash messages

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if not authenticated

db = SQLAlchemy(app)

# Create instance folder if it doesn't exist
instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)

# --- Enums for Dropdown Choices ---
# Using enums makes the choices consistent and easy to manage.

class RevenuePortfolioEnum(enum.Enum):
    TO = "T&O"
    MDCC = "MDCC"
    HEALTH_SOLUTIONS = "Health Solutions"
    INFRA_OPERATIONS = "Infrastructure Operations"
    SOLUTIONS_ENGINEERING = "Solutions Engineering"
    DATA_ANALYTICS = "Data and Analytics"
    PMO = "PMO"

class UnitEnum(enum.Enum):
    ADM = "ADM"
    IQE = "IQE"
    DX = "DX"
    ECAS = "ECAS"
    EAIS = "EAIS"

class CSGOwnerEnum(enum.Enum):
    AJAY = "Ajay"
    JOBY = "Joby"
    JUBY = "Juby"
    SHALINI = "Shalini"
    JASMEET = "Jasmeet"
    MANISH = "Manish"

class DeliveryOwnerEnum(enum.Enum):
    SUMEET = "Sumeet"
    PRASHANT = "Prashant"
    VIKAS = "Vikas"
    MAYANK = "Mayank"

class OriginatingRevenueTypeEnum(enum.Enum):
    A = "A-Current SoW"
    B = "B-SoW Extension"
    C = "C-Pipeline/RFP"
    D = "D-New Ideas"
    E = "E-Pitch Industry Ideas"
    F = "F-Incubate New Ideas"

class RevenueTypeEnum(enum.Enum):
    C = "C-Pipeline/RFP"
    D = "D-New Ideas"
    E = "E-Pitch Industry Ideas"
    F = "F-Incubate New Ideas"

# --- Database Model ---

class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(200), nullable=False)
    revenue_portfolio = db.Column(db.Enum(RevenuePortfolioEnum), nullable=False)
    unit = db.Column(db.Enum(UnitEnum), nullable=False)
    csg_owner = db.Column(db.Enum(CSGOwnerEnum), nullable=False)
    delivery_owner = db.Column(db.Enum(DeliveryOwnerEnum), nullable=False)
    originating_revenue_type = db.Column(db.Enum(OriginatingRevenueTypeEnum), nullable=False)
    revenue_type = db.Column(db.Enum(RevenueTypeEnum), nullable=False)
    conversion = db.Column(db.Integer, nullable=False) # Percentage
    ritm = db.Column(db.String(100))
    sow_number = db.Column(db.String(100))
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    revenue = db.Column(db.Float, nullable=False)
    client_director = db.Column(db.String(100))

    def __repr__(self):
        return f'<Opportunity {self.project_name}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    can_upload = db.Column(db.Boolean, default=False) # New field for upload permission

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper function to pass enums to all templates ---
@app.context_processor
def inject_enums():
    return {
        'RevenuePortfolioEnum': RevenuePortfolioEnum,
        'UnitEnum': UnitEnum,
        'CSGOwnerEnum': CSGOwnerEnum,
        'DeliveryOwnerEnum': DeliveryOwnerEnum,
        'OriginatingRevenueTypeEnum': OriginatingRevenueTypeEnum,
        'RevenueTypeEnum': RevenueTypeEnum,
        'current_user': current_user # Make current_user available in all templates
    }

# --- Helper function for processing form data ---
def _populate_opportunity_from_form(opportunity, form_data):
    """Helper function to populate an Opportunity object from form data."""
    opportunity.project_name=form_data['project_name']
    opportunity.revenue_portfolio=RevenuePortfolioEnum[form_data['revenue_portfolio']]
    opportunity.unit=UnitEnum[form_data['unit']]
    opportunity.csg_owner=CSGOwnerEnum[form_data['csg_owner']]
    opportunity.delivery_owner=DeliveryOwnerEnum[form_data['delivery_owner']]
    opportunity.originating_revenue_type=OriginatingRevenueTypeEnum[form_data['originating_revenue_type']]
    opportunity.revenue_type=RevenueTypeEnum[form_data['revenue_type']]
    opportunity.conversion=int(form_data['conversion'])
    opportunity.ritm=form_data['ritm']
    opportunity.sow_number=form_data['sow_number']
    opportunity.start_date=date.fromisoformat(form_data['start_date']) if form_data['start_date'] else None
    opportunity.end_date=date.fromisoformat(form_data['end_date']) if form_data['end_date'] else None
    opportunity.revenue=float(form_data['revenue'])
    opportunity.client_director=form_data['client_director']

# --- Web Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True) # Remember user for future sessions
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, can_upload=False) # New users cannot upload by default
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/')
@login_required
def index():
    opportunities = Opportunity.query.order_by(Opportunity.start_date.desc()).all()
    return render_template('index.html', opportunities=opportunities)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_opportunity():
    if request.method == 'POST':
        new_opp = Opportunity()
        _populate_opportunity_from_form(new_opp, request.form)
        db.session.add(new_opp)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('form.html', action="Add", opportunity=None)

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_opportunity(id):
    opp_to_edit = db.get_or_404(Opportunity, id)
    if request.method == 'POST':
        _populate_opportunity_from_form(opp_to_edit, request.form)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('form.html', action="Edit", opportunity=opp_to_edit)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_opportunity(id):
    opp_to_delete = db.get_or_404(Opportunity, id)
    db.session.delete(opp_to_delete)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/clone/<int:id>', methods=['POST'])
@login_required
def clone_opportunity(id):
    """Clones an existing opportunity and redirects to the edit page."""
    from sqlalchemy import inspect
    opp_to_clone = db.get_or_404(Opportunity, id)

    # Create a new opportunity object by copying attributes
    new_opp = Opportunity()
    mapper = inspect(Opportunity)
    for col in mapper.columns:
        # Don't copy the primary key
        if not col.primary_key:
            setattr(new_opp, col.key, getattr(opp_to_clone, col.key))

    # Differentiate the cloned opportunity's name
    new_opp.project_name = f"Clone of {opp_to_clone.project_name}"

    db.session.add(new_opp)
    db.session.commit()  # Commit to get the new ID

    flash(f'Successfully cloned "{opp_to_clone.project_name}". You are now editing the new copy.', 'success')
    return redirect(url_for('edit_opportunity', id=new_opp.id))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_spreadsheet():
    if not current_user.can_upload:
        flash('You do not have permission to upload spreadsheets.', 'warning')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in the request.', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading.', 'danger')
            return redirect(request.url)

        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            try:
                df = pd.read_excel(file, engine='openpyxl')

                # Define expected columns and their corresponding model attribute and type/enum
                expected_columns = {
                    'Opportunity/Project name': ('project_name', str),
                    'Revenue Portfolio': ('revenue_portfolio', RevenuePortfolioEnum),
                    'Unit': ('unit', UnitEnum),
                    'CSG Owner': ('csg_owner', CSGOwnerEnum),
                    'Delivery Owner': ('delivery_owner', DeliveryOwnerEnum),
                    'Originating Revenue Type': ('originating_revenue_type', OriginatingRevenueTypeEnum),
                    'Revenue Type': ('revenue_type', RevenueTypeEnum),
                    'Conversion': ('conversion', int),
                    'RITM': ('ritm', str),
                    'SOW': ('sow_number', str),
                    'Start Date': ('start_date', 'date'),
                    'End Date': ('end_date', 'date'),
                    'Revenue': ('revenue', float),
                    'Client Director': ('client_director', str)
                }

                # Validate that all expected columns are present
                if not all(col in df.columns for col in expected_columns.keys()):
                    missing = set(expected_columns.keys()) - set(df.columns)
                    flash(f'Spreadsheet is missing the following columns: {", ".join(missing)}', 'danger')
                    return redirect(request.url)

                # Process each row in the DataFrame
                for index, row in df.iterrows():
                    opp_data = {}
                    for col_name, (attr_name, attr_type) in expected_columns.items():
                        value = row.get(col_name)
                        if pd.isna(value):
                            opp_data[attr_name] = None
                            continue

                        if isinstance(attr_type, type) and issubclass(attr_type, enum.Enum):
                            # Find enum member by its value (e.g., "T&O")
                            enum_member = next((e for e in attr_type if e.value == value), None)
                            if enum_member is None:
                                raise ValueError(f'Invalid value "{value}" for column "{col_name}" on row {index + 2}')
                            opp_data[attr_name] = enum_member
                        elif attr_type == 'date':
                            opp_data[attr_name] = pd.to_datetime(value).date()
                        else:
                            opp_data[attr_name] = attr_type(value)

                    new_opp = Opportunity(**opp_data)
                    db.session.add(new_opp)

                db.session.commit()
                flash('Spreadsheet uploaded and data imported successfully!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during upload: {e}', 'danger')
                return redirect(request.url)

    return render_template('upload.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/download')
@login_required
def download_spreadsheet():
    """Downloads all data as an Excel file."""
    query = db.session.query(Opportunity).statement
    df = pd.read_sql(query, db.session.bind)

    # Convert enum objects to their string values for cleaner Excel output.
    for col in df.columns:
        # Check if the column's dtype is 'object' and its non-null values are enums.
        if df[col].dtype == 'object' and df[col].notna().any() and isinstance(df[col].dropna().iloc[0], enum.Enum):
            df[col] = df[col].apply(lambda x: x.value if x else None)

    output = io.BytesIO()
    # Use XlsxWriter to create a more professional-looking Excel file
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Opportunities')
        # Auto-adjust column widths
        for column in df:
            column_width = max(df[column].astype(str).map(len).max(), len(column))
            col_idx = df.columns.get_loc(column)
            writer.sheets['Opportunities'].set_column(col_idx, col_idx, column_width)

    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='opportunity_tracker.xlsx'
    )

# --- API Endpoints for Dashboard ---

@app.route('/api/revenue-by-unit-quarter')
@login_required
def revenue_by_unit_quarter():
    """API endpoint to get data for the 'Quarterly Revenue Projection' chart."""
    results = db.session.query(
        Opportunity.unit,
        extract('year', Opportunity.start_date).label('year'),
        extract('quarter', Opportunity.start_date).label('quarter'),
        func.sum(Opportunity.revenue * (Opportunity.conversion / 100.0)).label('projected_revenue')
    ).filter(
        Opportunity.start_date.isnot(None)
    ).group_by(
        Opportunity.unit, 'year', 'quarter'
    ).order_by(
        'year', 'quarter', Opportunity.unit
    ).all()

    # Process data into a format Chart.js can easily use
    data = {}
    for row in results:
        quarter_label = f"{int(row.year)} Q{int(row.quarter)}"
        if quarter_label not in data:
            data[quarter_label] = {}
        data[quarter_label][row.unit.value] = row.projected_revenue

    labels = sorted(data.keys())
    units = sorted(list(UnitEnum), key=lambda e: e.value)
    unit_labels = [u.value for u in units]
    datasets = []

    for unit in units:
        dataset = {
            'label': unit.value,
            'data': [data[label].get(unit.value, 0) for label in labels]
        }
        datasets.append(dataset)

    return jsonify({'labels': labels, 'datasets': datasets})

@app.cli.command("init-db")
def init_db_command():
    """Creates the database tables."""
    db.create_all()
    click.echo("Initialized the database.")


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates the database and tables if they don't exist
    app.run(host='0.0.0.0', debug=True)