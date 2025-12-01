from flask import Flask,  render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
app = Flask(__name__)


# Config 
from dotenv import load_dotenv
import os

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')

# Models

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

    role = db.relationship('Role', backref='users', lazy=True)
    
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32), unique=True, nullable=False)
    
class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(64), nullable=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    department = db.Column(db.String(32), unique=False, nullable=False)
    blacklist = db.Column(db.Boolean, default=False)
    
    
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    appointment_date = db.Column(db.Date, nullable=False) 
    appointment_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(32), nullable=False, default='booked')
    
    doctor = db.relationship('Doctor', backref='appointments', lazy=True)
    patient = db.relationship('User', backref='appointments', lazy=True)
    
class Treatment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=False)
    diagnosis = db.Column(db.String(256), nullable=False)
    notes = db.Column(db.String(512), nullable=True)
    prescribed_medication = db.Column(db.String(256), nullable=True)
    
    appointment = db.relationship('Appointment', backref='treatments', lazy=True)
    
class Availability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    morning = db.Column(db.Boolean, default=False)
    afternoon = db.Column(db.Boolean, default=False)
    evening = db.Column(db.Boolean, default=False)
    
    doctor = db.relationship('Doctor', backref='availabilities', lazy=True)
    
    
with app.app_context():
    db.create_all()
    
    admin = User.query.filter_by(role_id=1).first()
    if not admin:
        password_hash = generate_password_hash('admin')
        admin = User(username = 'admin', passhash=password_hash, role_id=1, name='Admin')
        db.session.add(admin)
        db.session.commit()
        
    role = Role.query.filter_by(name='admin').first()
    if not role:
        role = Role(name='admin')
        db.session.add(role)
        db.session.commit()
    
    role = Role.query.filter_by(name='patient').first()
    if not role:
        role = Role(name='patient')
        db.session.add(role)
        db.session.commit()
        
    role = Role.query.filter_by(name='doctor').first()
    if not role:
        role = Role(name='doctor')
        db.session.add(role)
        db.session.commit()

# decorater for auth required
def auth_required(role=None):
    def decorator(func):
        @wraps(func)
        def inner(*args, **kwargs):
            if 'username' not in session:
                flash('Please login to access this page.', 'danger')
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('You do not have permission to access this page.', 'danger')
                # Optional: redirect to homepage or profile based on your app logic
                return redirect(url_for('welcome'))
            return func(*args, **kwargs)
        return inner
    return decorator

# Routes


#default route

@app.route('/')
def welcome():
    return render_template('welcome.html')



#Login Routes

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
        
    if not username or not password:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('Username does not exist. Please Register', 'danger')
        return redirect(url_for('register'))
    
    if not check_password_hash(user.passhash, password):
        flash('Incorrect password.', 'danger')
        return redirect(url_for('login'))
    
    if (user.username == username) and (check_password_hash(user.passhash, password)) and user.role_id == 2:
        session['username'] = username
        session['role'] = user.role.name
        flash('Logged in successfully.', 'success')
        return redirect(url_for('patient_dashboard'))
    
    elif (user.username == username) and (check_password_hash(user.passhash, password)) and user.role_id == 1:
        session['username'] = username
        session['role'] = user.role.name
        flash('Admin Logged in successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    elif (user.username == username) and (check_password_hash(user.passhash, password)) and user.role_id == 3:
        session['username'] = username
        session['role'] = user.role.name
        flash('Doctor Logged in successfully.', 'success')
        return redirect(url_for('doctor_dashboard'))
    
    
    
    
    
# General Routes ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    name = request.form.get('name')
    
    if not username or not password or not confirm_password:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('register'))
    
    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(username=username).first()

    
    if user: 
        flash('Username already exists.', 'danger')
        return redirect(url_for('register'))
    
    passhash = generate_password_hash(password)
    
    new_user = User(name=name, username=username, passhash=passhash, role_id=2)  # Default role_id=2 for patients
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))



@app.route('/index')
def index():
    return render_template('index.html')

    
# Patient Routes ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    
@app.route('/profile')
@auth_required()
def profile():
    user = User.query.filter_by(username=session['username']).first()

    return render_template('profile.html', user=user)


@app.route('/profile', methods=['POST'])
@auth_required()
def profile_post():
    username = request.form.get('username')
    currpassword = request.form.get('currpassword')
    newpassword = request.form.get('newpassword')
    confirmnewpassword = request.form.get('cnewpassword')
    name = request.form.get('name')
    
    if (not username) or (not currpassword) or (not newpassword) or (not confirmnewpassword):
        flash('Please fill out all the fields', 'danger')
        return redirect(url_for('profile'))
    
    user = User.query.filter_by(username=session['username']).first()

    
    if not check_password_hash(user.passhash, currpassword):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('profile'))
    
    if username != user.username:
        existing_user = User.query.filter_by(username=session['username']).first()

        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('profile'))
        
    if newpassword or confirmnewpassword:
        if newpassword !=  confirmnewpassword:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('profile'))
        user.passhash = generate_password_hash(newpassword)
        
    user.username = username
    user.name = name
    db.session.commit()
    flash('Profile updated successfully.', 'success')
    return redirect(url_for('profile'))

@app.route('/logout')
@auth_required()
def logout():
    session.pop('username')
    session.pop('role')
    flash('Logged out successfully.','success') 
    return redirect(url_for('welcome'))

@app.route('/patient_dashboard')
@auth_required('patient')
def patient_dashboard():
    patient= User.query.filter_by(username=session['username']).first()
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    doctor = Doctor.query.filter_by(blacklist= False).all()
    return render_template('patient_dashboard.html', user = patient, appointments=appointments, doctors = doctor)

@app.route('/book_appointment/<doc_username>', methods=['GET'])
@auth_required('patient')
def book_appointment(doc_username):
    doctor = Doctor.query.filter_by(username=doc_username, blacklist=False).first_or_404()
    
    # 1. Generate dates for the next 7 days
    days = []
    today = date.today()
    for i in range(7):
        days.append(today + timedelta(days=i))

    # 2. Fetch all availability records for this doctor
    # We grab them all to build the map efficiently
    records = Availability.query.filter_by(doctor_id=doctor.id).all()
    
    # 3. Create a lookup map for the template to define Button Colors
    # Key: "YYYY-MM-DD" -> Value: { 'morning': True/False, 'afternoon': True/False ... }
    availability_map = {}
    for r in records:
        d_str = r.date.strftime('%Y-%m-%d')
        availability_map[d_str] = {
            'morning': r.morning,
            'afternoon': r.afternoon,
            'evening': r.evening
        }

    return render_template('book_appointment.html', doctor=doctor, days=days, availability_map=availability_map)


@app.route('/book_appointment/<doc_username>', methods=['POST'])
@auth_required('patient')
def book_appointment_post(doc_username):
    doctor = Doctor.query.filter_by(username=doc_username, blacklist=False).first_or_404()
    patient = User.query.filter_by(username=session['username']).first()
    
    date_str = request.form.get('date')
    time_str = request.form.get('time') 
    
    if not date_str or not time_str:
        flash('Invalid selection.', 'danger')
        return redirect(url_for('book_appointment', doc_username=doc_username))
    
    try:
        appointment_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        time_obj = datetime.strptime(time_str, '%H:%M').time()
        
        final_datetime = datetime.combine(appointment_date, time_obj)
        
    except ValueError:
        flash('Error processing date/time.', 'danger')
        return redirect(url_for('book_appointment', doc_username=doc_username))
    
    av = Availability.query.filter_by(doctor_id=doctor.id, date=appointment_date).first()
    is_available = False
    
    if av:
        if time_str == '08:00' and av.morning:
            is_available = True
            av.morning = False  
            
        elif time_str == '12:00' and av.afternoon:
            is_available = True
            av.afternoon = False
            
        elif time_str == '16:00' and av.evening:
            is_available = True
            av.evening = False  
            
    if not is_available:
        flash('Sorry, that slot is no longer available.', 'danger')
        return redirect(url_for('book_appointment', doc_username=doc_username))

    new_appointment = Appointment(
        patient_id=patient.id, 
        doctor_id=doctor.id, 
        appointment_date=appointment_date, 
        appointment_time=final_datetime, 
        status='booked'
    )
    
    db.session.add(new_appointment)
    db.session.commit()
    
    formatted_time = time_obj.strftime("%I:%M %p")
    flash(f'Successfully booked with Dr. {doctor.name or doctor.username} on {date_str} at {formatted_time}.', 'success')    
    return redirect(url_for('patient_dashboard'))

# Admin Routes ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


@app.route('/adddoc')
def adddoc():
    return render_template('add_doctor.html')

@app.route('/adddoc', methods=['POST'])
@auth_required('admin')
def adddoc_post():
    username = request.form.get('docusername')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    name = request.form.get('docname')
    department = request.form.get('department')
    
    if not username or not password or not confirm_password:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('adddoc'))
    
    if password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('adddoc'))
    
    doc = User.query.filter_by(username=username).first()

    if doc: 
        flash('Username already exists.', 'danger')
        return redirect(url_for('adddoc'))
    else:
        passhash = generate_password_hash(password)
        
        new_user = User(name=name, username=username, passhash=passhash, role_id=3)  # Default role_id=3 for doctors
        db.session.add(new_user)
        db.session.flush()
        
        new_doc = Doctor(name=name, username=username,user_id=new_user.id, department=department) 
        db.session.add(new_doc)
        db.session.commit()
        return redirect(url_for('viewdoc'))


@app.route('/updatedoc/<username>', methods=['GET'])
@auth_required('admin')
def updatedoc(username):
    doctor = Doctor.query.filter_by(username=username).first_or_404()
    return render_template('update_doctor.html', doctor=doctor)


@app.route('/updatedoc/<username>', methods=['POST'])
@auth_required('admin')
def updatedoc_post(username):
    doctor = Doctor.query.filter_by(username=username).first_or_404()
    user = User.query.filter_by(id=doctor.user_id).first()
    
    username = request.form.get('username')
    name = request.form.get('name')
    department = request.form.get('department')
    currpassword = request.form.get('currpassword')
    newpassword = request.form.get('newpassword')
    confirmnewpassword = request.form.get('confirmnewpassword')
    name = request.form.get('name')
    
    if (not username) or (not currpassword) or (not department):
        flash('Please fill out all required fields', 'danger')
        return redirect(url_for('updatedoc', username=doctor.username))

    # Only validate new passwords if user entered them
    if newpassword or confirmnewpassword:
        if not newpassword or not confirmnewpassword:
            flash('Please fill out both new password fields', 'danger')
            return redirect(url_for('updatedoc', username=doctor.username))
        if newpassword != confirmnewpassword:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('updatedoc', username=doctor.username))

    
    if not check_password_hash(user.passhash, currpassword):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('updatedoc', username=doctor.username))
    
    if username != user.username:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('updatedoc', username=doctor.username))

        
    if newpassword or confirmnewpassword:
        if newpassword != confirmnewpassword:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('updatedoc', username=doctor.username))
        
        
    user.username = username
    user.name = name
    doctor.username = username
    doctor.name = name
    doctor.department = department
    user.passhash = generate_password_hash(newpassword)
    
    db.session.commit()
    flash('Doctor profile updated successfully.', 'success')
    return redirect(url_for('viewdoc'))

@app.route('/blacklist_doctor/<username>', methods=['POST'])
@auth_required('admin')
def blacklist_doctor(username):
    doctor = Doctor.query.filter_by(username=username).first_or_404()
    doctor.blacklist = True
    db.session.commit()
    flash(f"Doctor {doctor.name or doctor.username} has been blacklisted.", "success")
    return redirect(url_for('viewdoc'))

@app.route('/unblacklist_doctor/<username>', methods=['POST'])
@auth_required('admin')
def unblacklist_doctor(username):
    doctor = Doctor.query.filter_by(username=username).first_or_404()
    doctor.blacklist = False
    db.session.commit()
    flash(f"Doctor {doctor.name or doctor.username} has been unblacklisted.", "success")
    return redirect(url_for('viewdoc'))

@app.route('/remove_doctor/<username>', methods=['POST'])
@auth_required('admin')
def remove_doctor(username):
    doctor = Doctor.query.filter_by(username=username).first_or_404()
    # Optionally, remove the user record and their appointments/treatments as well
    user = User.query.get(doctor.user_id)
    db.session.delete(doctor)
    if user:
        db.session.delete(user)
    db.session.commit()
    flash(f"Doctor {doctor.username} has been removed.", "success")
    return redirect(url_for('viewdoc'))

@app.route('/admin_dashboard')
@auth_required('admin')
def admin_dashboard():
    search = request.args.get('search_query', '').strip()

    if search:
        patients = User.query.filter(User.role_id == 2).filter(
            (User.name.ilike(f'%{search}%')) | (User.username.ilike(f'%{search}%')) ).all()
        doctors = Doctor.query.filter((Doctor.name.ilike(f'%{search}%')) | (Doctor.username.ilike(f'%{search}%')) | (Doctor.department.ilike(f'%{search}%'))).all()

        if not patients and not doctors:
            flash('No results found for your search.', 'info')
            return redirect(url_for('admin_dashboard'))

        # Render search results page with patients or doctors
        if patients:
            return render_template('view_patient.html', patients=patients)
        if doctors:
            return render_template('view_doctor.html', doctors=doctors)

    else:
        patients = User.query.filter_by(role_id=2).all()
        doctors = Doctor.query.all()

    patient_count = len(patients)
    doctor_count = len(doctors)
    appointment_count = Appointment.query.count()

    return render_template('admin_dashboard.html', patients=patients, doctors=doctors, patient_count=patient_count, doctor_count=doctor_count, appointment_count=appointment_count, search_query=search)


@app.route('/view_user/<role>/<username>')
@auth_required('admin')
def view_user(role, username):
    if role == 'patient':
        user = User.query.filter_by(username=username, role_id=2).first_or_404()
    elif role == 'doctor':
        user = Doctor.query.filter_by(username=username).first_or_404()
    else:
        flash('Invalid user role.', 'danger')
        return redirect(url_for('admin_dashboard'))

    return render_template('view_user.html', user=user, role=role)

                           
@app.route('/viewdoc')
@auth_required('admin')
def viewdoc():
    doctors = Doctor.query.all()
    return render_template('view_doctor.html', doctors=doctors)

@app.route('/viewpatient')
@auth_required('admin')
def viewpatient():
    patients = User.query.filter_by(role_id=2).all()
    return render_template('view_patient.html', patients=patients)


@app.route('/updatepatient/<username>', methods=['GET'])
@auth_required('admin')
def updatepatient(username):
    patient = User.query.filter_by(username=username).first_or_404()
    return render_template('update_patient.html', patient=patient)


@app.route('/updatepatient/<username>', methods=['POST'])
@auth_required('admin')
def updatepatient_post(username):
    patient = User.query.filter_by(username=username, role_id=2).first_or_404()
    
    username_form = request.form.get('username')
    currpassword = request.form.get('currpassword')
    newpassword = request.form.get('newpassword')
    confirmnewpassword = request.form.get('cnewpassword')
    name = request.form.get('name')

    if not username_form or not currpassword or not name:
        flash('Please fill out all required fields', 'danger')
        return redirect(url_for('updatepatient', username=patient.username))

    # Only validate new passwords if user entered them
    if newpassword or confirmnewpassword:
        if not newpassword or not confirmnewpassword:
            flash('Please fill out both new password fields', 'danger')
            return redirect(url_for('updatepatient', username=patient.username))
        if newpassword != confirmnewpassword:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('updatepatient', username=patient.username))

    if not check_password_hash(patient.passhash, currpassword):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('updatepatient', username=patient.username))

    if username_form != patient.username:
        existing_user = User.query.filter_by(username=username_form).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('updatepatient', username=patient.username))

    # Update patient details
    patient.username = username_form
    patient.name = name

    if newpassword:
        patient.passhash = generate_password_hash(newpassword)

    db.session.commit()
    flash('Patient profile updated successfully.', 'success')
    return redirect(url_for('viewpatient'))


@app.route('/remove_patient/<username>', methods=['POST'])
@auth_required('admin')
def remove_patient(username):
    patient = User.query.filter_by(username=username, role_id=2).first_or_404()
    db.session.delete(patient)
    flash(f"Patient {patient.username} has been removed.", "success")
    return redirect(url_for('viewpatient'))

@app.route('/viewappointment')
@auth_required('admin')
def viewappointment():
    appointments = Appointment.query.join(User, Appointment.patient_id == User.id).join(Doctor, Appointment.doctor_id == Doctor.id).all()
    return render_template('view_appointment.html', appointments=appointments)




# Doctor Routes ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/doctor_dashboard')
@auth_required('doctor')
def doctor_dashboard():
    doctor = Doctor.query.filter_by(username=session['username']).first()
    appointments = Appointment.query.filter_by(doctor_id=doctor.id).order_by(Appointment.appointment_date, Appointment.appointment_time).all()
    my_patients = set([appt.patient for appt in appointments])
    return render_template('doctor_dashboard.html', appointments=appointments, doctor=doctor, patients=my_patients)



@app.route('/set_availability')
@auth_required('doctor')
def set_availability():
    doctor = Doctor.query.filter_by(username=session['username']).first()
    
    days = []
    today = date.today()
    for i in range(7):
        days.append(today + timedelta(days=i))

    records = Availability.query.filter_by(doctor_id=doctor.id).all()

    active_slots = []
    for r in records:
        date_str = r.date.strftime('%Y-%m-%d')
        
        if r.morning:
            active_slots.append(f"{date_str}_08:00")
        if r.afternoon:
            active_slots.append(f"{date_str}_12:00")
        if r.evening:
            active_slots.append(f"{date_str}_16:00")

    return render_template('set_availability.html', days=days, active_slots=active_slots)


@app.route('/toggle_availability', methods=['POST'])
@auth_required('doctor')
def toggle_availability():
    doctor = Doctor.query.filter_by(username=session['username']).first()
    
    date_str = request.form.get('date')
    time_slot = request.form.get('time_slot')
    
    if not date_str or not time_slot:
        flash('Invalid request', 'danger')
        return redirect(url_for('set_availability'))

    try:
        clicked_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        availability = Availability.query.filter_by(doctor_id=doctor.id, date=clicked_date).first()
        
        if not availability:
            availability = Availability(doctor_id=doctor.id, date=clicked_date)
            db.session.add(availability)
        
        if time_slot == '08:00':
            availability.morning = not availability.morning
        elif time_slot == '12:00':
            availability.afternoon = not availability.afternoon
        elif time_slot == '16:00':
            availability.evening = not availability.evening
            
        db.session.commit()
        
    except ValueError:
        flash('Invalid date format', 'danger')
    
    return redirect(url_for('set_availability'))

@app.route('/consultation/<int:appointment_id>', methods =['GET'])
@auth_required('doctor')
def consultation(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    doctor = Doctor.query.filter_by(username=session['username']).first()
    if appointment.doctor.id != doctor.id:
        flash('You do not have permission to access this consultation.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    patient_history = Treatment.query.join(Appointment).filter(
        Appointment.patient_id == appointment.patient.id,
        Appointment.id != appointment.id
    ).order_by(Appointment.appointment_date.desc()).all()
    return render_template('consultation.html', appointment=appointment, history=patient_history)

@app.route('/complete_consultation/<int:appointment_id>', methods =['POST'])
@auth_required('doctor')
def complete_consultation(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    doctor = Doctor.query.filter_by(username=session['username']).first()
    
    if appointment.doctor.id != doctor.id:
        flash('You do not have permission to access this consultation.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    diagnosis = request.form.get('diagnosis')
    prescription = request.form.get('prescription')
    notes = request.form.get('notes')
    
    
    if not diagnosis:
        flash('Diagnosis is required.', 'danger')
        return redirect(url_for('consultation', appointment_id=appointment_id))
    
    new_treatment = Treatment(
        appointment_id=appointment.id,
        diagnosis=diagnosis,
        prescribed_medication=prescription,
        notes=notes
        )
    
    appointment.status = 'completed'
    db.session.add(new_treatment)
    db.session.commit()
    
    flash('Consultation details saved successfully.', 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor_cancel_appointment/<int:id>', methods=['POST'])
@auth_required('doctor')
def doctor_cancel_appointment(id):

    appt = Appointment.query.get_or_404(id)
    doctor = Doctor.query.filter_by(username=session['username']).first()
    

    if appt.doctor_id != doctor.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('doctor_dashboard'))
    

    av = Availability.query.filter_by(doctor_id=doctor.id, date=appt.appointment_date).first()
    
    if av:

        time_str = appt.appointment_time.strftime("%H:%M")
        
        if time_str == "08:00":
            av.morning = True 
        elif time_str == "12:00":
            av.afternoon = True
        elif time_str == "16:00":
            av.evening = True

    appt.status = 'cancelled'
    db.session.commit()
    
    flash('Appointment cancelled successfully.', 'info')
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor_view_patient/<username>')
@auth_required('doctor')
def doctor_view_patient(username):
    patient = User.query.filter_by(username=username, role_id=2).first_or_404()
    
    return render_template('view_user_doctor.html', user=patient, role='patient')



# Debug

if __name__ == "__main__":
    app.run(debug=True)

