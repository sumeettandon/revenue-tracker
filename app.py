import os
import enum
import io
from functools import wraps
from datetime import date
import json

import pandas as pd
from xlsxwriter.workbook import Workbook
from xlsxwriter.utility import xl_col_to_name
from dotenv import load_dotenv
import click # Keep click here as it's used for CLI commands
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from sqlalchemy import func, extract, inspect
from sqlalchemy.orm import joinedload
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

# --- Database Models ---

class RevenuePortfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<RevenuePortfolio {self.name}>'

class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<Unit {self.name}>'

class CSGOwner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<CSGOwner {self.name}>'

class DeliveryOwner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<DeliveryOwner {self.name}>'

class OriginatingRevenueType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<OriginatingRevenueType {self.name}>'

class RevenueType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    def __repr__(self): return f'<RevenueType {self.name}>'

class QuarterlyRevenue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    opportunity_id = db.Column(db.Integer, db.ForeignKey('opportunity.id', ondelete='CASCADE'), nullable=False)
    financial_year = db.Column(db.Integer, nullable=False)
    quarter = db.Column(db.Integer, nullable=False)
    revenue = db.Column(db.Float, nullable=False)

    __table_args__ = (db.UniqueConstraint('opportunity_id', 'financial_year', 'quarter', name='uq_opp_fy_q'),)

    def __repr__(self):
        return f'<QuarterlyRevenue FY{self.financial_year}-Q{self.quarter} for Opp {self.opportunity_id}>'
class Opportunity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(200), nullable=False)
    revenue_portfolio_id = db.Column(db.Integer, db.ForeignKey('revenue_portfolio.id'), nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey('unit.id'), nullable=False)
    csg_owner_id = db.Column(db.Integer, db.ForeignKey('csg_owner.id'), nullable=False)
    delivery_owner_id = db.Column(db.Integer, db.ForeignKey('delivery_owner.id'), nullable=False)
    originating_revenue_type_id = db.Column(db.Integer, db.ForeignKey('originating_revenue_type.id'), nullable=False)
    revenue_type_id = db.Column(db.Integer, db.ForeignKey('revenue_type.id'), nullable=False)
    conversion = db.Column(db.Integer, nullable=False) # Percentage
    ritm = db.Column(db.String(100))
    sow_number = db.Column(db.String(100))
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    revenue = db.Column(db.Float, nullable=False)
    client_director = db.Column(db.String(100))

    revenue_portfolio = db.relationship('RevenuePortfolio', backref=db.backref('opportunities', lazy=True))
    unit = db.relationship('Unit', backref=db.backref('opportunities', lazy=True))
    csg_owner = db.relationship('CSGOwner', backref=db.backref('opportunities', lazy=True))
    delivery_owner = db.relationship('DeliveryOwner', backref=db.backref('opportunities', lazy=True))
    originating_revenue_type = db.relationship('OriginatingRevenueType', backref=db.backref('opportunities', lazy=True))
    revenue_type = db.relationship('RevenueType', backref=db.backref('opportunities', lazy=True))
    quarterly_revenues = db.relationship('QuarterlyRevenue', backref='opportunity', cascade="all, delete-orphan", lazy='dynamic')

    def __repr__(self):
        return f'<Opportunity {self.project_name}>'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    can_upload = db.Column(db.Boolean, default=False) # New field for upload permission
    is_admin = db.Column(db.Boolean, default=False) # New field for admin permission

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper Functions ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You must be an admin to view this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_financial_quarter():
    """
    Calculates the current financial year and quarter.
    Assumes the financial year starts in April.
    """
    today = date.today()
    month = today.month
    year = today.year

    if month >= 4:
        financial_year = year + 1
        financial_quarter = ((month - 4) // 3) + 1
    else:
        financial_year = year
        financial_quarter = 4
    return financial_year, financial_quarter

def _get_revenue_by_dimension(model_class, year_filter):
    """Helper to generate revenue data grouped by a specific dimension."""
    query = (db.session.query(
        model_class.name.label('dimension_name'),
        func.sum(Opportunity.revenue * (Opportunity.conversion / 100.0)).label('projected_revenue')
    ).select_from(Opportunity).join(getattr(Opportunity, model_class.__tablename__)))

    if year_filter:
        query = query.filter(extract('year', Opportunity.start_date) == year_filter)

    results = query.group_by('dimension_name').order_by('dimension_name').all()
    labels = [row.dimension_name for row in results]
    data_values = [row.projected_revenue for row in results]
    datasets = [{'label': 'Projected Revenue', 'data': data_values}]
    return jsonify({'labels': labels, 'datasets': datasets})

@app.context_processor
def inject_lookup_data():
    return {
        'all_revenue_portfolios': RevenuePortfolio.query.order_by(RevenuePortfolio.name).all(),
        'all_units': Unit.query.order_by(Unit.name).all(),
        'all_csg_owners': CSGOwner.query.order_by(CSGOwner.name).all(),
        'all_delivery_owners': DeliveryOwner.query.order_by(DeliveryOwner.name).all(),
        'all_originating_revenue_types': OriginatingRevenueType.query.order_by(OriginatingRevenueType.name).all(),
        'all_revenue_types': RevenueType.query.order_by(RevenueType.name).all(),
        'current_user': current_user # Make current_user available in all templates
    }

# --- Helper function for processing form data ---
def _populate_opportunity_from_form(opportunity, form_data):
    """Helper function to populate an Opportunity object from form data."""
    opportunity.project_name=form_data['project_name']
    opportunity.revenue_portfolio_id=int(form_data['revenue_portfolio'])
    opportunity.unit_id=int(form_data['unit'])
    opportunity.csg_owner_id=int(form_data['csg_owner'])
    opportunity.delivery_owner_id=int(form_data['delivery_owner'])
    opportunity.originating_revenue_type_id=int(form_data['originating_revenue_type'])
    opportunity.revenue_type_id=int(form_data['revenue_type'])
    opportunity.conversion=int(form_data['conversion'])
    opportunity.ritm=form_data['ritm']
    opportunity.sow_number=form_data['sow_number']
    opportunity.start_date=date.fromisoformat(form_data['start_date']) if form_data['start_date'] else None
    opportunity.end_date=date.fromisoformat(form_data['end_date']) if form_data['end_date'] else None
    opportunity.client_director=form_data['client_director']

    # Handle quarterly revenues
    if opportunity.id: # if editing, clear existing to replace them
        opportunity.quarterly_revenues.delete()
        db.session.flush() # flush the delete to avoid constraint issues

    total_quarterly_revenue = 0
    for key, value in form_data.items():
        if key.startswith('quarter_FY') and value:
            try:
                revenue_value = float(value)
                parts = key.split('_') # e.g., ['quarter', 'FY2026', 'Q4']
                fy = int(parts[1][2:])
                q = int(parts[2][1:])
                qr = QuarterlyRevenue(financial_year=fy, quarter=q, revenue=revenue_value)
                opportunity.quarterly_revenues.append(qr)
                total_quarterly_revenue += revenue_value
            except (ValueError, IndexError):
                # Ignore invalid or malformed fields
                continue
    
    # Update total revenue based on the sum of the quarterly breakdown
    opportunity.revenue = total_quarterly_revenue

# --- Web Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=True) # Remember user for future sessions
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
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
        return redirect(url_for('dashboard'))
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

        new_user = User(username=username, can_upload=False, is_admin=False) # New users are not admins
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/')
@login_required
def dashboard():
    # Get distinct years from the database to populate the filter
    years_query = db.session.query(extract('year', Opportunity.start_date)).distinct().order_by(extract('year', Opportunity.start_date).desc())
    available_years = [y[0] for y in years_query if y[0] is not None]

    # Get selected year from query params, default to the most recent year if available
    selected_year = request.args.get('year', type=int)
    if selected_year is None and available_years:
        selected_year = available_years[0]

    current_fy, current_fq = get_current_financial_quarter()

    return render_template(
        'dashboard.html',
        available_years=available_years,
        selected_year=selected_year,
        current_fy=current_fy,
        current_fq=current_fq
    )

@app.route('/opportunities')
@login_required
def opportunities():
    query = db.session.query(Opportunity)

    # Search
    search_term = request.args.get('search', type=str, default='').strip()
    if search_term:
        query = query.filter(Opportunity.project_name.ilike(f'%{search_term}%'))

    # Filtering
    filter_unit_id = request.args.get('filter_unit', type=int)
    if filter_unit_id:
        query = query.filter(Opportunity.unit_id == filter_unit_id)

    filter_csg_owner_id = request.args.get('filter_csg_owner', type=int)
    if filter_csg_owner_id:
        query = query.filter(Opportunity.csg_owner_id == filter_csg_owner_id)

    filter_revenue_portfolio_id = request.args.get('filter_revenue_portfolio', type=int)
    if filter_revenue_portfolio_id:
        query = query.filter(Opportunity.revenue_portfolio_id == filter_revenue_portfolio_id)

    # Sorting
    sort_by = request.args.get('sort_by', 'start_date')
    sort_direction = request.args.get('sort_direction', 'desc')

    sortable_columns = {
        'project_name': Opportunity.project_name,
        'unit': Unit.name,
        'revenue_portfolio': RevenuePortfolio.name,
        'revenue': Opportunity.revenue,
        'conversion': Opportunity.conversion,
        'start_date': Opportunity.start_date,
        'end_date': Opportunity.end_date,
        'csg_owner': CSGOwner.name,
    }

    if sort_by in sortable_columns:
        sort_column = sortable_columns[sort_by]

        # Join with related tables if sorting by their columns
        if sort_by == 'unit': query = query.join(Unit)
        if sort_by == 'revenue_portfolio': query = query.join(RevenuePortfolio)
        if sort_by == 'csg_owner': query = query.join(CSGOwner)

        if sort_direction == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

    # Make a mutable copy of request.args to pass to the template.
    # We remove 'page', 'sort_by', and 'sort_direction' because they are
    # handled explicitly by the pagination and sorting controls.
    filter_values = request.args.copy()
    filter_values.pop('page', None)
    filter_values.pop('sort_by', None)
    filter_values.pop('sort_direction', None)

    page = request.args.get('page', 1, type=int)
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    opportunities = pagination.items

    return render_template('index.html', opportunities=opportunities, pagination=pagination,
                           sort_by=sort_by, sort_direction=sort_direction,
                           filter_values=filter_values)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_opportunity():
    if request.method == 'POST':
        new_opp = Opportunity()
        _populate_opportunity_from_form(new_opp, request.form)
        db.session.add(new_opp)
        db.session.commit()
        flash(f'Successfully added opportunity "{new_opp.project_name}".', 'success')
        return redirect(url_for('opportunities'))
    return render_template('form.html', action="Add", opportunity=None, quarterly_revenues_json='[]')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_opportunity(id):
    opp_to_edit = db.get_or_404(Opportunity, id)
    if request.method == 'POST':
        _populate_opportunity_from_form(opp_to_edit, request.form)
        db.session.commit()
        flash(f'Successfully updated opportunity "{opp_to_edit.project_name}".', 'success')
        return redirect(url_for('opportunities'))
    
    quarterly_revenues_json = json.dumps([
        {'financial_year': qr.financial_year, 'quarter': qr.quarter, 'revenue': qr.revenue}
        for qr in opp_to_edit.quarterly_revenues
    ])
    return render_template('form.html', action="Edit", opportunity=opp_to_edit, quarterly_revenues_json=quarterly_revenues_json)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_opportunity(id):
    opp_to_delete = db.get_or_404(Opportunity, id)
    db.session.delete(opp_to_delete)
    db.session.commit()
    return redirect(url_for('opportunities'))

@app.route('/clone/<int:id>', methods=['POST'])
@login_required
def clone_opportunity(id):
    """Clones an existing opportunity and redirects to the edit page."""
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
        return redirect(url_for('dashboard'))

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

                # Pre-load lookup data to convert names to IDs
                lookups = {
                    'revenue_portfolio_id': {p.name: p.id for p in RevenuePortfolio.query.all()},
                    'unit_id': {u.name: u.id for u in Unit.query.all()},
                    'csg_owner_id': {o.name: o.id for o in CSGOwner.query.all()},
                    'delivery_owner_id': {o.name: o.id for o in DeliveryOwner.query.all()},
                    'originating_revenue_type_id': {o.name: o.id for o in OriginatingRevenueType.query.all()},
                    'revenue_type_id': {o.name: o.id for o in RevenueType.query.all()},
                }

                column_map = {
                    'Opportunity/Project name': 'project_name',
                    'Revenue Portfolio': 'revenue_portfolio_id',
                    'Unit': 'unit_id',
                    'CSG Owner': 'csg_owner_id',
                    'Delivery Owner': 'delivery_owner_id',
                    'Originating Revenue Type': 'originating_revenue_type_id',
                    'Revenue Type': 'revenue_type_id',
                    'Conversion': 'conversion',
                    'RITM': 'ritm',
                    'SOW': 'sow_number',
                    'Start Date': 'start_date',
                    'End Date': 'end_date',
                    'Client Director': 'client_director',
                }

                # Validate that all expected columns are present
                if not all(col in df.columns for col in column_map.keys()):
                    missing = set(column_map.keys()) - set(df.columns)
                    flash(f'Spreadsheet is missing the following columns: {", ".join(missing)}', 'danger')
                    return redirect(request.url)

                # Process each row in the DataFrame
                for index, row in df.iterrows():
                    opp_data = {}
                    for col_name, attr_name in column_map.items():
                        value = row.get(col_name)
                        if pd.isna(value):
                            opp_data[attr_name] = None
                        elif attr_name in lookups:
                            lookup_id = lookups[attr_name].get(str(value))
                            if lookup_id is None:
                                raise ValueError(f'Invalid value "{value}" for column "{col_name}" on row {index + 2}')
                            opp_data[attr_name] = lookup_id
                        elif attr_name in ['start_date', 'end_date']:
                            opp_data[attr_name] = pd.to_datetime(value).date() if value else None
                        else:
                            opp_data[attr_name] = value

                    # Revenue is now calculated from quarterly data, so default to 0 on upload.
                    # User must edit the opportunity to add the breakdown.
                    new_opp = Opportunity(**opp_data, revenue=0.0)
                    db.session.add(new_opp)

                db.session.commit()
                flash('Spreadsheet uploaded and data imported successfully!', 'success')
                flash('Please edit the newly added opportunities to add the quarterly revenue breakdown.', 'info')
                return redirect(url_for('opportunities'))
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred during upload: {e}', 'danger')
                return redirect(request.url)

    return render_template('upload.html')

@app.route('/download')
@login_required
def download_spreadsheet():
    """Downloads all data as an Excel file."""
    # Eagerly load related objects to avoid N+1 query problem
    opportunities = Opportunity.query.options(
        joinedload(Opportunity.revenue_portfolio),
        joinedload(Opportunity.unit),
        joinedload(Opportunity.csg_owner),
        joinedload(Opportunity.delivery_owner),
        joinedload(Opportunity.originating_revenue_type),
        joinedload(Opportunity.revenue_type)
    ).all()

    # Prepare data for DataFrame
    data_for_df = [
        {
            'Opportunity/Project name': opp.project_name,
            'Revenue Portfolio': opp.revenue_portfolio.name,
            'Unit': opp.unit.name,
            'CSG Owner': opp.csg_owner.name,
            'Delivery Owner': opp.delivery_owner.name,
            'Originating Revenue Type': opp.originating_revenue_type.name,
            'Revenue Type': opp.revenue_type.name,
            'conversion': opp.conversion,
            'ritm': opp.ritm,
            'SOW': opp.sow_number,
            'Start Date': opp.start_date,
            'End Date': opp.end_date,
            'revenue': opp.revenue,
            'Client Director': opp.client_director,
        }
        for opp in opportunities
    ]
    df = pd.DataFrame(data_for_df)

    output = io.BytesIO()
    # Use XlsxWriter to create a more professional-looking Excel file
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Opportunities')
        # Auto-adjust column widths
        for column in df:
            column_width = max(df[column].astype(str).map(len).max(), len(column)) + 1
            col_idx = df.columns.get_loc(column)
            writer.sheets['Opportunities'].set_column(col_idx, col_idx, column_width)

    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='opportunity_tracker.xlsx'
    )

@app.route('/download-template')
@login_required
def download_template():
    """Generates and serves the Excel template for uploading opportunities."""
    output = io.BytesIO()
    workbook = Workbook(output, {'in_memory': True})
    worksheet = workbook.add_worksheet('Opportunities')

    # Define headers from the upload column map
    headers = [
        'Opportunity/Project name', 'Revenue Portfolio', 'Unit', 'CSG Owner',
        'Delivery Owner', 'Originating Revenue Type', 'Revenue Type',
        'Conversion', 'RITM', 'SOW', 'Start Date', 'End Date',
        'Client Director'
    ]
    worksheet.write_row('A1', headers)
    worksheet.freeze_panes(1, 0) # Freeze header row

    # --- Add data validation dropdowns for lookup columns ---
    lookups = {
        'B': RevenuePortfolio.query.order_by(RevenuePortfolio.name).all(),
        'C': Unit.query.order_by(Unit.name).all(),
        'D': CSGOwner.query.order_by(CSGOwner.name).all(),
        'E': DeliveryOwner.query.order_by(DeliveryOwner.name).all(),
        'F': OriginatingRevenueType.query.order_by(OriginatingRevenueType.name).all(),
        'G': RevenueType.query.order_by(RevenueType.name).all(),
    }
    lookup_sheet = workbook.add_worksheet('Lookups')
    lookup_sheet.hide()
    for col_idx, (col_letter, items) in enumerate(lookups.items()):
        values = [item.name for item in items]
        lookup_sheet.write_column(f'{chr(65 + col_idx)}1', values)
        formula = f"=Lookups!${chr(65 + col_idx)}$1:${chr(65 + col_idx)}${len(values)}"
        worksheet.data_validation(f'{col_letter}2:{col_letter}1048576',
                                  {'validate': 'list', 'source': formula})

    # Add data validation for 'Conversion'
    conversions = [25, 50, 75, 90, 100]
    lookup_sheet.write_column('G1', conversions)
    worksheet.data_validation('H2:H1048576', {'validate': 'list', 'source': f'=Lookups!$G$1:$G${len(conversions)}'})

    # Add formatting and comments for guidance
    date_format = workbook.add_format({'num_format': 'yyyy-mm-dd'})
    worksheet.set_column('K:L', 12, date_format)
    worksheet.write_comment('K1', 'Enter dates in YYYY-MM-DD format.')
    worksheet.write_comment('L1', 'Enter dates in YYYY-MM-DD format.')

    worksheet.autofit()
    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='opportunity_upload_template.xlsx'
    )

# --- API Endpoints for Dashboard ---

@app.route('/api/revenue-by-unit-quarter')
@login_required
def revenue_by_unit_quarter():
    """API endpoint to get data for the 'Quarterly Revenue Projection' chart."""
    query = (db.session.query(
        Unit.name.label('unit_name'),
        extract('year', Opportunity.start_date).label('year'),
        extract('quarter', Opportunity.start_date).label('quarter'),
        func.sum(Opportunity.revenue * (Opportunity.conversion / 100.0)).label('projected_revenue')
    ).select_from(Opportunity).join(Opportunity.unit).filter(
        Opportunity.start_date.isnot(None)
    ))

    year = request.args.get('year', type=int)
    if year:
        query = query.filter(extract('year', Opportunity.start_date) == year)

    results = query.group_by(
        'unit_name', 'year', 'quarter'
    ).order_by(
        'year', 'quarter', 'unit_name'
    ).all()

    # Process data into a format Chart.js can easily use
    data = {}
    for row in results:
        quarter_label = f"{int(row.year)} Q{int(row.quarter)}"
        if quarter_label not in data:
            data[quarter_label] = {}
        data[quarter_label][row.unit_name] = row.projected_revenue

    labels = sorted(data.keys())
    units = [u.name for u in Unit.query.order_by(Unit.name).all()]
    datasets = []

    for unit_name in units:
        dataset = {
            'label': unit_name,
            'data': [data[label].get(unit_name, 0) for label in labels]
        }
        datasets.append(dataset)

    return jsonify({'labels': labels, 'datasets': datasets})

@app.route('/api/revenue-by-originating-type')
@login_required
def revenue_by_originating_type():
    """API endpoint for revenue by originating revenue type, grouped by unit."""
    query = (db.session.query(
        Unit.name.label('unit_name'),
        OriginatingRevenueType.name.label('origin_type_name'),
        func.sum(Opportunity.revenue * (Opportunity.conversion / 100.0)).label('projected_revenue')
    ).select_from(Opportunity).join(Opportunity.unit).join(Opportunity.originating_revenue_type))

    year = request.args.get('year', type=int)
    if year:
        query = query.filter(extract('year', Opportunity.start_date) == year)

    results = query.group_by(
        'unit_name',
        'origin_type_name'
    ).order_by(
        'unit_name',
        'origin_type_name'
    ).all()

    # Process data for Chart.js
    data = {}
    for row in results:
        origin_type_label = row.origin_type_name
        if origin_type_label not in data:
            data[origin_type_label] = {}
        data[origin_type_label][row.unit_name] = row.projected_revenue

    labels = [e.name for e in OriginatingRevenueType.query.order_by(OriginatingRevenueType.name).all()]
    units = [u.name for u in Unit.query.order_by(Unit.name).all()]
    datasets = []

    for unit_name in units:
        dataset = {
            'label': unit_name,
            'data': [data.get(label, {}).get(unit_name, 0) for label in labels],
        }
        datasets.append(dataset)

    return jsonify({'labels': labels, 'datasets': datasets})

@app.route('/api/revenue-by-csg-owner')
@login_required
def revenue_by_csg_owner():
    """API endpoint for revenue by CSG owner."""
    query = (db.session.query(
        CSGOwner.name.label('csg_owner_name'),
        func.sum(Opportunity.revenue * (Opportunity.conversion / 100.0)).label('projected_revenue')
    ).select_from(Opportunity).join(Opportunity.csg_owner))

    year = request.args.get('year', type=int)
    if year:
        query = query.filter(extract('year', Opportunity.start_date) == year)

    results = query.group_by(
        'csg_owner_name'
    ).order_by(
        'csg_owner_name'
    ).all()

    labels = [row.csg_owner_name for row in results]
    data_values = [row.projected_revenue for row in results]

    datasets = [{'label': 'Projected Revenue', 'data': data_values}]

    return jsonify({'labels': labels, 'datasets': datasets})

@app.route('/api/revenue-by-unit-current-quarter')
@login_required
def revenue_by_unit_current_quarter():
    """API endpoint for revenue by unit for the current financial quarter."""
    fy, fq = get_current_financial_quarter()

    results = (db.session.query(
        Unit.name.label('unit_name'),
        func.sum(QuarterlyRevenue.revenue * (Opportunity.conversion / 100.0)).label('projected_revenue')
    ).select_from(QuarterlyRevenue)
     .join(QuarterlyRevenue.opportunity)
     .join(Opportunity.unit)
     .filter(QuarterlyRevenue.financial_year == fy)
     .filter(QuarterlyRevenue.quarter == fq)
     .group_by(Unit.name)
     .order_by(Unit.name)
    ).all()

    labels = [row.unit_name for row in results]
    data_values = [row.projected_revenue for row in results]

    datasets = [{'label': 'Projected Revenue', 'data': data_values}]

    return jsonify({'labels': labels, 'datasets': datasets})

@app.route('/api/revenue-by-delivery-owner')
@login_required
def revenue_by_delivery_owner():
    """API endpoint for revenue by Delivery owner."""
    year = request.args.get('year', type=int)
    return _get_revenue_by_dimension(DeliveryOwner, year)

@app.route('/api/revenue-by-revenue-portfolio')
@login_required
def revenue_by_revenue_portfolio():
    """API endpoint for revenue by Revenue Portfolio."""
    year = request.args.get('year', type=int)
    return _get_revenue_by_dimension(RevenuePortfolio, year)

@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/user/<int:id>/toggle-upload', methods=['POST'])
@admin_required
def toggle_user_upload(id):
    user = db.get_or_404(User, id)
    if user.id == current_user.id:
        flash("Admins cannot change their own upload permissions.", "warning")
    else:
        user.can_upload = not user.can_upload
        db.session.commit()
        flash(f"Upload permission for {user.username} has been updated.", "success")
    return redirect(url_for('manage_users'))

@app.route('/admin/user/<int:id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_user_admin(id):
    user = db.get_or_404(User, id)
    if user.id == current_user.id:
        flash("Admins cannot revoke their own admin status.", "warning")
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"Admin status for {user.username} has been updated.", "success")
    return redirect(url_for('manage_users'))

# --- Admin Routes ---

LOOKUP_MODELS = {
    'unit': {'class': Unit, 'title': 'Units'},
    'csg_owner': {'class': CSGOwner, 'title': 'CSG Owners'},
    'delivery_owner': {'class': DeliveryOwner, 'title': 'Delivery Owners'},
    'originating_revenue_type': {'class': OriginatingRevenueType, 'title': 'Originating Revenue Types'},
    'revenue_type': {'class': RevenueType, 'title': 'Revenue Types'},
    'revenue_portfolio': {'class': RevenuePortfolio, 'title': 'Revenue Portfolios'}
}

@app.route('/admin')
@admin_required
def admin_index():
    return render_template('admin/index.html', models=LOOKUP_MODELS)

@app.route('/admin/manage/<model_name>')
@admin_required
def manage_lookup_table(model_name):
    if model_name not in LOOKUP_MODELS:
        flash(f"Invalid model type: {model_name}", "danger")
        return redirect(url_for('admin_index'))

    model_info = LOOKUP_MODELS[model_name]
    ModelClass = model_info['class']
    items = ModelClass.query.order_by(ModelClass.name).all()
    return render_template('admin/list_generic.html',
                           items=items,
                           title=model_info['title'],
                           model_name=model_name)

@app.route('/admin/manage/<model_name>/add', methods=['GET', 'POST'])
@admin_required
def add_lookup_item(model_name):
    if model_name not in LOOKUP_MODELS:
        return redirect(url_for('admin_index'))

    model_info = LOOKUP_MODELS[model_name]
    ModelClass = model_info['class']

    if request.method == 'POST':
        name = request.form['name']
        if not name:
            flash('Name cannot be empty.', 'danger')
        elif ModelClass.query.filter_by(name=name).first():
            flash(f'An item with the name "{name}" already exists.', 'danger')
        else:
            new_item = ModelClass(name=name)
            db.session.add(new_item)
            db.session.commit()
            flash(f'Successfully added "{name}".', 'success')
            return redirect(url_for('manage_lookup_table', model_name=model_name))

    return render_template('admin/form_generic.html', title=f"Add New {model_info['title'][:-1]}", item=None, model_name=model_name)

@app.route('/admin/manage/<model_name>/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_lookup_item(model_name, id):
    if model_name not in LOOKUP_MODELS: return redirect(url_for('admin_index'))
    ModelClass = LOOKUP_MODELS[model_name]['class']
    item = db.get_or_404(ModelClass, id)

    if request.method == 'POST':
        item.name = request.form['name']
        db.session.commit()
        flash(f'Successfully updated item.', 'success')
        return redirect(url_for('manage_lookup_table', model_name=model_name))

    return render_template('admin/form_generic.html', title=f"Edit {LOOKUP_MODELS[model_name]['title'][:-1]}", item=item, model_name=model_name)

@app.route('/admin/manage/<model_name>/delete/<int:id>', methods=['POST'])
@admin_required
def delete_lookup_item(model_name, id):
    if model_name not in LOOKUP_MODELS: return redirect(url_for('admin_index'))
    ModelClass = LOOKUP_MODELS[model_name]['class']
    item = db.get_or_404(ModelClass, id)
    db.session.delete(item)
    db.session.commit()
    flash(f'Successfully deleted item.', 'success')
    return redirect(url_for('manage_lookup_table', model_name=model_name))

# --- CLI Commands ---

@app.cli.command("init-db")
def init_db_command():
    """Creates the database tables."""
    db.create_all()
    click.echo("Initialized the database.")

@app.cli.command("seed-db")
def seed_db_command():
    """Seeds the database with initial lookup data."""
    lookups = {
        RevenuePortfolio: ["T&O", "MDCC", "Health Solutions", "Infrastructure Operations", "Solutions Engineering", "Data and Analytics", "PMO"],
        Unit: ["ADM", "IQE", "DX", "ECAS", "EAIS"],
        CSGOwner: ["Ajay", "Joby", "Juby", "Shalini", "Jasmeet", "Manish"],
        DeliveryOwner: ["Sumeet", "Prashant", "Vikas", "Mayank"],
        OriginatingRevenueType: ["A-Current SoW", "B-SoW Extension", "C-Pipeline/RFP", "D-New Ideas", "E-Pitch Industry Ideas", "F-Incubate New Ideas"],
        RevenueType: ["C-Pipeline/RFP", "D-New Ideas", "E-Pitch Industry Ideas", "F-Incubate New Ideas"]
    }

    for model, values in lookups.items():
        for value in values:
            if not model.query.filter_by(name=value).first():
                db.session.add(model(name=value))

    db.session.commit()
    click.echo("Seeded the database with lookup data.")

@app.cli.command("grant-admin")
@click.argument('username')
def grant_admin(username):
    """Grants admin privileges to a user."""
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        click.echo(f"User '{username}' has been granted admin privileges.")
    else:
        click.echo(f"User '{username}' not found.")