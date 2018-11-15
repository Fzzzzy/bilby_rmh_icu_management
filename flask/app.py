from flask import Flask, render_template, flash, session, redirect, url_for, logging, request, jsonify 
from flask_mysqldb import MySQL
from functools import wraps
from wtforms import Form, DateField, StringField, TextAreaField, PasswordField, validators, StringField, SubmitField, DateTimeField, SelectField
from passlib.hash import sha256_crypt
import datetime

app = Flask(__name__)

# init database connection settings
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'swen90014'
app.config['MYSQL_PASSWORD'] = 'swen90014'
app.config['MYSQL_DB'] = 'rmh'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

# check if user has logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# check if user is an administrator
def is_administrator(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if  session.get('staffType') == 'admin' or session.get('staffType') == 'super':
            return f(*args, **kwargs)
        else:
            flash('Unauthorized Access', 'danger')
            return redirect(url_for('index'))
    return wrap

#======================================================================Login & Logout=================================================================#
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods = ['GET','POST'])
def login():   
    # check if logged_in
    if session.get('logged_in'):
        if session['staffType'] == 'admin' or session['staffType'] == 'super':
            return redirect(url_for('accountManagement')) 
        else:
            return redirect(url_for('patientProfile')) 
    else:
        loginForm = LoginForm(request.form)
        if request.method == 'POST' and loginForm.validate(): 
            # validate with database
            email = loginForm.email.data
            password_candidate = loginForm.password.data
            cur = mysql.connection.cursor()
            result = cur.execute("SELECT * FROM staffs where email = %s", [email])
            # email correct
            if result > 0:
                data = cur.fetchone()
                password = data['password']
                # password correct
                if sha256_crypt.verify(password_candidate, password):
                    # app.logger.error('PASSWORD MATCHED')
                    # add to session
                    session['logged_in'] = True
                    session['email'] = data['email']
                    session['staffName'] = data['firstname'] +' '+ data['lastname']
                    session['staffType'] = data['staffType']
                    cur.close()
                    if session['staffType'] == 'admin' or session['staffType'] == 'super':
                        # jump to management page
                        return redirect(url_for('accountManagement'))
                    else:
                        return redirect(url_for('patientProfile'))
                # wrong password
                else:
                    #app.logger.error('WRONG PASSWORD')
                    cur.close()
                    flash('WRONG PASSWORD','danger')
            # no email matched in database  
            else:
                #app.logger.error('NO USER')
                cur.close()
                flash('NO USER MATCHED','danger')
        # render login page
    return render_template('login.html', form=loginForm)

@app.route('/about')
def about():
    # render about page
    return render_template('about.html')

@app.route('/documents')
def documents():
    # render documents page
    return render_template('documents.html')

@app.route('/logout')
@is_logged_in
def logout():   
    session.clear()
    return redirect(url_for('index'))

#======================================================================Account Management=================================================================#
@app.route('/accountManagement', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def accountManagement():
    addAccountForm = AddAccountForm()
    editAccountForm = EditAccountForm()
    
    staffs = 'empty'
    # get accounts from database
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM staffs")
    if result > 0:
        staffs = cur.fetchall()
        cur.close()
    else:
        cur.close()
        flash('No Record','danger')
    return render_template('manageAccount.html', staffs = staffs, addAccountForm = addAccountForm, editAccountForm = editAccountForm)

# Search Account Front End control

@app.route('/accountManagement/addAccount', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def addAccount():
    addAccountForm = AddAccountForm(request.form)
    if request.method == 'POST' and addAccountForm.validate():
        #jsonify(status='ok')
        email = addAccountForm.email.data
        firstname = addAccountForm.firstname.data
        lastname = addAccountForm.lastname.data
        staffType = addAccountForm.staffType.data
        password = sha256_crypt.hash(addAccountForm.password.data)
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM staffs where email = %s", [email])
        if result > 0:
            flash('Staff Already Exist','danger')
        else:
            cur.execute("INSERT INTO staffs (email, firstname, lastname, staffType, password) values (%s,%s,%s,%s,%s)", [email,firstname,lastname,staffType,password] )
            #commit
            mysql.connection.commit()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('accountManagement'))
    
@app.route('/accountManagement/editAccount', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def editAccount():
    editAccountForm = EditAccountForm(request.form)
    if request.method == 'POST' and editAccountForm.validate():
        email = editAccountForm.email.data
        firstname = editAccountForm.firstname.data
        lastname = editAccountForm.lastname.data
        staffType = editAccountForm.staffType.data
        password = sha256_crypt.hash(editAccountForm.password.data)
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM staffs where email = %s", [email])
        if result > 0:
            statement = "UPDATE staffs SET firstname=%s, lastname=%s, staffType=%s, password=%s where email=%s"
            cur.execute(statement, [firstname,lastname,staffType,password,email])
            #commit
            mysql.connection.commit()
            flash('Success','success')
        else:
            flash('Staff Not Exist','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('accountManagement'))
   
@app.route('/accountManagement/deleteAccount/<string:email>', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def deleteAccount(email):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM staffs WHERE email = %s", [email])
    if result > 0:
        cur.execute("DELETE FROM staffs WHERE email = %s", [email])
        #commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        cur.close()
        flash('Staff Not Exist','danger')
    return redirect(url_for('accountManagement'))

@app.route('/accountManagement/resetPassAccount/<string:email>', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def resetPassAccount(email):
    password = sha256_crypt.hash('123456')
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM staffs WHERE email = %s", [email])
    if result > 0:
        cur.execute("UPDATE staffs SET password = %s WHERE email = %s", [password,email])
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        cur.close()
        flash('Staff Not Exist','danger')
    return redirect(url_for('accountManagement'))

#======================================================================Medicine Management=================================================================#
@app.route('/medicineManagement', methods = ['GET','POST'])
@is_logged_in
def medicineManagement():
    # search form
    medicineForm = MedicineForm()
    medicines = 'empty'
    # get accounts from database
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM medicines")
    if result > 0:
        medicines = cur.fetchall()
        cur.close()
    else:
        flash('No Record','danger')

    return render_template('manageMedicine.html',medicines=medicines, medicineForm=medicineForm)

@app.route('/medicineManagement/addMedicine', methods = ['GET','POST'])
@is_logged_in
def addMedicine():
    medicineForm = MedicineForm(request.form)
    if request.method == 'POST' and medicineForm.validate():
        medicineName = medicineForm.medicineName.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines where medicineName = %s", [medicineName])
        if result > 0:
            flash('Medicine Already Exist','danger')
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName] )
            #commit
            mysql.connection.commit()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('medicineManagement'))
    
@app.route('/medicineManagement/editMedicine/<string:medicineID>', methods = ['GET','POST'])
@is_logged_in
def editMedicine(medicineID):
    medicineForm = MedicineForm(request.form)
    if request.method == 'POST' and medicineForm.validate():
        medicineName = medicineForm.medicineName.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines where medicineName = %s", [medicineName])
        if result > 0:
            flash('Medicine Already Exist','danger')
        else:
            cur.execute("UPDATE medicines SET medicineName = %s WHERE medicineID = %s", [medicineName,medicineID])
            #commit
            mysql.connection.commit()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('medicineManagement'))
   
@app.route('/medicineManagement/deleteMedicine/<string:medicineID>', methods = ['GET','POST'])
@is_logged_in
def deleteMedicine(medicineID):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM medicines WHERE medicineID = %s", [medicineID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('medicineManagement'))

# Add/ delete / edit/ search  routes need to be specified

#===========================================================================Research=================================================================#
@app.route('/research', methods = ['GET','POST'])
@is_logged_in
def research():
    return render_template('research.html')
#========================================================================Patient Profile=================================================================#
@app.route('/patientProfile', methods = ['GET','POST'])
@is_logged_in
def patientProfile():
    patientForm = PatientForm()
    admissionForm = AdmissionForm()
    searchURN = SearchURN()
    mcForm = McForm()
    patient = None
    admissions = None
    ICUadmissions = None
    mcICU = None
    return render_template('patientProfile.html', patient = patient, admissions = admissions, ICUadmissions = ICUadmissions, mcICU = mcICU,
                            patientForm = patientForm, admissionForm = admissionForm, searchURN = searchURN, mcForm=mcForm)

@app.route('/patientProfile/searchPatient', methods = ['GET','POST'])
@is_logged_in
def searchPatient():
    # select patient by URN (returned from form)
    # should be a json can get urn by paitent['urn']
    # select admission by URN
    searchURN = SearchURN(request.form)
    if request.method == 'POST' and searchURN.validate():
        urn = searchURN.urn.data
        return redirect(url_for('showSearchResult',urn = urn))
    else:
        flash('Invalid URN','danger')
        return redirect(url_for('patientProfile'))
    # select mmp
    # select ICUadmission
    # select mcICU
    # show admissions (JINJA)

@app.route('/patientProfile/showSearchResult/<string:urn>', methods = ['GET','POST'])
@is_logged_in
def showSearchResult(urn):
    # select patient by URN (returned from form)
    # should be a json can get urn by paitent['urn']
    # select admission by URN
    patientForm = PatientForm()
    admissionForm = AdmissionForm()
    searchURN = SearchURN()
    mcForm = McForm()
    cur = mysql.connection.cursor()
    patient = None
    admissions = None
    ICUadmissions = None
    mcICU = None
    result = cur.execute("SELECT * FROM patients WHERE urn = %s", [urn])
    if result > 0:
        patient = cur.fetchone()
        session['urn'] = urn
        result = cur.execute("SELECT * FROM admissions WHERE  urn = %s", [urn]) 
        if result > 0:    
            admissions = cur.fetchall()
        result = cur.execute("SELECT * FROM ICUadmissions")
        if result > 0:
            ICUadmissions = cur.fetchall()
        result = cur.execute("SELECT * FROM mcICU")
        if result > 0:
            mcICU = cur.fetchall()                
    else:
        flash('Patient not found','danger')
    cur.close()
    # select mmp
    # select ICUadmission
    # select mcICU
    # show admissions (JINJA)
    return render_template('patientProfile.html',patient = patient, admissions = admissions, ICUadmissions = ICUadmissions, mcICU = mcICU,mcForm=mcForm,patientForm = patientForm,searchURN=searchURN,admissionForm=admissionForm)

@app.route('/patientProfile/addPatient', methods = ['GET','POST'])
@is_logged_in
def addPatient():
    patientForm = PatientForm(request.form)
    if request.method == 'POST' and patientForm.validate():
        #jsonify(status='ok')
        urn = patientForm.urn.data
        firstname = patientForm.firstname.data
        lastname = patientForm.lastname.data
        dateOfBirth = patientForm.dateOfBirth.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM patients where urn = %s", [urn])
        if result > 0:
            flash('Patient Already Exist','danger')
        else:
            cur.execute("INSERT INTO patients (urn, firstname, lastname, dateOfBirth) values (%s,%s,%s,%s)", [urn,firstname,lastname,dateOfBirth] )
            #commit
            mysql.connection.commit()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('patientProfile'))
    # if valid (not exist urn)
    # Insert patient
    # cur = mysql.connection.cursor()
    # result = cur.execute("SELECT * FROM patients where urn = %s", urn) # should get urn by paitent['urn'] here
    #if result > 0:
    #    cur.close()
    #    flash('Staff Already Exist','danger')
    #    return redirect(url_for('researchs'))
    #else:
    #    insert
    #return render_template('research.html')

@app.route('/patientProfile/editPatient/<string:urn>', methods = ['GET','POST'])
@is_logged_in
def editPatient(urn):
    patientForm = PatientForm(request.form)
    if request.method == 'POST' and patientForm.validate():
        new_urn = patientForm.urn.data
        firstname = patientForm.firstname.data
        lastname = patientForm.lastname.data
        dateOfBirth = patientForm.dateOfBirth.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM patients where urn = %s", [new_urn])
        if result > 0:
            cur.execute("UPDATE patients SET firstname = %s, lastname = %s, dateOfBirth = %s WHERE urn = %s", [firstname,lastname,dateOfBirth,urn])
            #commit
            mysql.connection.commit()
        else:
            cur.execute("UPDATE patients SET urn = %s, firstname = %s, lastname = %s, dateOfBirth = %s WHERE urn = %s", [new_urn,firstname,lastname,dateOfBirth,urn])
            #commit
            mysql.connection.commit()
        flash('Success','success')    
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('showSearchResult',urn = new_urn))

@app.route('/patientProfile/deletePatient/<string:urn>', methods = ['GET','POST'])
@is_logged_in
def deletePatient(urn):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM patients WHERE urn = %s", [urn])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('patientProfile'))
    # if valid
    # Insert ICUAdmission
    # Insert mcICU
    # Insert mcICUDischarge

@app.route('/patientProfile/addAdmission', methods = ['GET','POST'])
@is_logged_in
def addAdmission():
    admissionForm = AdmissionForm(request.form)
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO admissions (urn, dateFrom, dateTo) values (%s,%s,%s)", [session['urn'],dateFrom,dateTo])
        #commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('showSearchResult',urn = session['urn']))

@app.route('/patientProfile/editAdmission/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def editAdmission(admissionID):
    admissionForm = AdmissionForm(request.form)
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        cur = mysql.connection.cursor()
        cur.execute("UPDATE admissions SET dateFrom = %s, dateTo = %s WHERE admissionID = %s", [dateFrom,dateTo,admissionID])
        #commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('showSearchResult',urn = session['urn']))

@app.route('/patientProfile/deleteAdmission/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def deleteAdmission(admissionID):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM admissions WHERE admissionID = %s", [admissionID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('showSearchResult',urn = session['urn']))

@app.route('/patientProfile/addICUAdmission/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def addICUAdmission(admissionID):
    admissionForm = AdmissionForm(request.form)
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO ICUadmissions (admissionID, dateFrom, dateTo) values (%s,%s,%s)", [admissionID,dateFrom,dateTo])
        #commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('showSearchResult',urn = session['urn']))
    # if valid
    # Insert ICUAdmission
    # Insert mcICU
    # Insert mcICUDischarge


@app.route('/patientProfile/editICUAdmission/<string:icuAdmissionID>', methods = ['GET','POST'])
@is_logged_in
def editICUAdmission(icuAdmissionID):
    admissionForm = AdmissionForm(request.form)
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        cur = mysql.connection.cursor()
        cur.execute("UPDATE icuAdmissions SET dateFrom = %s, dateTo = %s WHERE icuAdmissionID = %s", [dateFrom,dateTo,icuAdmissionID])
        #commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    return redirect(url_for('showSearchResult',urn = session['urn']))

@app.route('/patientProfile/deleteICUAdmission/<string:icuAdmissionID>', methods = ['GET','POST'])
@is_logged_in
def deleteICUAdmission(icuAdmissionID):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM icuAdmissions WHERE icuAdmissionID = %s", [icuAdmissionID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('showSearchResult',urn = session['urn']))
    # if valid
    # delete ICUAdmission (all related inserts)

@app.route('/patientProfile/addMCICU/<string:icuAdmissionID>', methods = ['GET','POST'])
@is_logged_in
def addMCICU(icuAdmissionID):
    mcForm = McForm(request.form)
    # if valid
    # Insert mcICU
    if request.method == 'POST' and mcForm.validate():
        dateFrom = mcForm.dateFrom.data
        dateTo = mcForm.dateTo.data
        type = mcForm.type.data
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO mcICU (icuAdmissionID, dateFrom, dateTo, type) values (%s,%s,%s,%s)", [icuAdmissionID,dateFrom,dateTo,type])
        mysql.connection.commit()
        cur.close()
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('showSearchResult',urn = session['urn']))

@app.route('/patientProfile/editMCICU/<string:mcID>', methods = ['GET','POST'])
@is_logged_in
def editMCICU(mcID):
    mcForm = McForm(request.form)
    # if valid
    # Insert mcICU
    if request.method == 'POST' and mcForm.validate():
        dateFrom = mcForm.dateFrom.data
        dateTo = mcForm.dateTo.data
        cur = mysql.connection.cursor()
        cur.execute("UPDATE mcICU SET dateFrom = %s, dateTo = %s WHERE mcID = %s", [dateFrom,dateTo,mcID])
        mysql.connection.commit()
        cur.close()
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('showSearchResult',urn = session['urn']))

@app.route('/patientProfile/deleteMCICU/<string:mcID>', methods = ['GET','POST'])
@is_logged_in
def deleteMCICU(mcID):
    # if valid
    # delete mcICU (all related inserts)
     # Delete where mmpID
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mcICU WHERE mcID = %s", [mcID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('showSearchResult',urn = session['urn']))

#===========================================================================MMP=================================================================#
@app.route('/mmp/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def mmp(admissionID):
    # Select all where mmp number
    # show
    mmpRecordForm = MmpRecordForm()
    mmpRecords = None
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM admissions where admissionID = %s", [admissionID])
    admission = cur.fetchone()
    result = cur.execute("SELECT * FROM mmpRecords where admissionID = %s", [admissionID]) # should get urn by paitent['urn'] here
    session['admissionID'] = admissionID
    if result > 0:
        mmpRecords = cur.fetchall()
    cur.close()
    return render_template('mmp.html',admission=admission, mmpRecords=mmpRecords, mmpRecordForm = mmpRecordForm)

@app.route('/mmp/addMmpRecord', methods = ['GET','POST'])
@is_logged_in
def addMmpRecord():
    mmpRecordForm = MmpRecordForm(request.form)
    # Insert where mmpID
    # Insert medicine
    if request.method == 'POST' and mmpRecordForm.validate():
        medicineName = mmpRecordForm.medicineName.data
        dose = mmpRecordForm.dose.data
        route = mmpRecordForm.route.data
        frequency = mmpRecordForm.frequency.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        if result > 0:    
            cur.execute("INSERT INTO mmpRecords (admissionID, medicineName, dose,route,frequency) values (%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,dose,route,frequency]) 
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            cur.execute("INSERT INTO mmpRecords (admissionID, medicineName,dose,route,frequency) values (%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,dose,route,frequency]) 
        mysql.connection.commit() 
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('mmp', admissionID = session['admissionID']))

@app.route('/mmp/editMmpRecord/<string:mmpRecordID>', methods = ['GET','POST'])
@is_logged_in
def editMmpRecord(mmpRecordID):
    mmpRecordForm = MmpRecordForm(request.form)
    if request.method == 'POST' and mmpRecordForm.validate():
        medicineName = mmpRecordForm.medicineName.data
        dose = mmpRecordForm.dose.data
        route = mmpRecordForm.route.data
        frequency = mmpRecordForm.frequency.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        if result > 0:    
            cur.execute("UPDATE mmpRecords SET medicineName = %s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,dose,route,frequency,mmpRecordID])
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            cur.execute("UPDATE mmpRecords SET medicineName = %s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,dose,route,frequency,mmpRecordID])
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('mmp', admissionID = session['admissionID']))

@app.route('/mmp/deleteMmpRecord/<string:mmpRecordID>', methods = ['GET','POST'])
@is_logged_in
def deleteMmpRecord(mmpRecordID):
    # Delete where mmpID
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mmpRecords WHERE mmpRecordID = %s", [mmpRecordID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('mmp', admissionID = session['admissionID']))

#===========================================================================MCD=================================================================#
@app.route('/mcd/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def mcd(admissionID):
    # Select all where mmp number
    # show
    mcRecordForm = McRecordForm()
    mcRecords = None
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM admissions where admissionID = %s", [admissionID])
    admission = cur.fetchone()
    result = cur.execute("SELECT * FROM mcHospitalDischargeRecords where admissionID = %s", [admissionID]) # should get urn by paitent['urn'] here
    session['admissionID'] = admissionID
    if result > 0:
        mcRecords = cur.fetchall()
    cur.close()
    return render_template('mcd.html',admission=admission, mcRecords=mcRecords, mcRecordForm = mcRecordForm)

@app.route('/mcd/addMcdRecord', methods = ['GET','POST'])
@is_logged_in
def addMcdRecord():
    mcRecordForm = McRecordForm(request.form)
    # Insert where mmpID
    # Insert medicine
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date = mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        if result > 0:    
            cur.execute("INSERT INTO mcHospitalDischargeRecords (admissionID, medicineName,date, dose,route,frequency) values (%s,%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,date,dose,route,frequency]) 
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            cur.execute("INSERT INTO mcHospitalDischargeRecords (admissionID, medicineName,date,dose,route,frequency) values (%s,%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,date,dose,route,frequency]) 
        mysql.connection.commit() 
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('mcd', admissionID = session['admissionID']))

@app.route('/mcd/editMcdRecord/<string:mcHDRecordID>', methods = ['GET','POST'])
@is_logged_in
def editMcdRecord(mcHDRecordID):
    mcRecordForm = McRecordForm(request.form)
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date = mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        if result > 0:    
            cur.execute("UPDATE mcHospitalDischargeRecords SET medicineName = %s, date=%s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,date,dose,route,frequency,mcHDRecordID])
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            cur.execute("UPDATE mmpRecords SET medicineName = %s, date=%s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,date,dose,route,frequency,mcHDRecordID])
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('mcd', admissionID = session['admissionID']))

@app.route('/mmp/deleteMcdRecord/<string:mcHDRecordID>', methods = ['GET','POST'])
@is_logged_in
def deleteMcdRecord(mcHDRecordID):
    # Delete where mmpID
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mcHospitalDischargeRecords WHERE mcHDRecordID = %s", [mcHDRecordID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('mcd', admissionID = session['admissionID']))


#============================================================================MC=================================================================#
@app.route('/mc/<string:mcID>', methods = ['GET','POST'])
@is_logged_in
def mcICU(mcID):
    mcRecordForm = McRecordForm()
    mcRecords = None
    session['mcID'] = mcID
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM mcICU where mcID = %s", [mcID])
    mcICU = cur.fetchone()
    result = cur.execute("SELECT * FROM mcICURecords where mcID = %s", [mcID]) # should get urn by paitent['urn'] here
    if result > 0:
        mcRecords = cur.fetchall()    
    cur.close()
    return render_template('mc.html', mcRecords=mcRecords, mcRecordForm=mcRecordForm, mcICU=mcICU)

@app.route('/mc/addMcRecord', methods = ['GET','POST'])
@is_logged_in
def addMcRecord():
    # Insert where mcID
    # Insert medicine
    mcRecordForm = McRecordForm(request.form)
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date= mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM medicines")
        result = cur.fetchall()  
        medicineExist = False    
        for medicine in result:
            if medicine['medicineName'] == medicineName:
                medicineExist = True
        if medicineExist == True:
            cur.execute("INSERT INTO mcICURecords (mcID, medicineName, date, dose, route, frequency) values (%s,%s,%s,%s,%s,%s)", [session['mcID'],medicineName,date,dose,route,frequency])    
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            cur.execute("INSERT INTO mcICURecords (mcID, medicineName, date,dose, route, frequency) values (%s,%s,%s,%s,%s,%s)", [session['mcID'],medicineName,date,dose,route,frequency])
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('mcICU', mcID = session['mcID']))

@app.route('/mc/editMcRecord/<string:mcICURecordID>', methods = ['GET','POST'])
@is_logged_in
def editMcRecord(mcICURecordID):
    mcRecordForm = McRecordForm(request.form)
    # Edit where mcID
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date = mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM medicines")
        result = cur.fetchall()
        medicineExist = False       
        for medicine in result:
            if medicine['medicineName'] == medicineName:
                medicineExist = True
        if medicineExist == True:
            cur.execute("UPDATE mcICURecords SET medicineName = %s, date = %s, dose = %s, route = %s, frequency = %s WHERE mcICURecordID = %s", [medicineName,date,dose,route,frequency,mcICURecordID])
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            cur.execute("UPDATE mcICURecords SET medicineName = %s, date = %s, dose = %s, route = %s, frequency = %s WHERE mcICURecordID = %s", [medicineName,date,dose,route,frequency,mcICURecordID])
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    return redirect(url_for('mcICU', mcID = session['mcID']))
   
@app.route('/mc/deleteMcRecord/<string:mcICURecordID>', methods = ['GET','POST'])
@is_logged_in
def deleteMcRecord(mcICURecordID):
    # Delete where mcID
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mcICURecords WHERE mcICURecordID = %s", [mcICURecordID])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('mcICU', mcID = session['mcID']))

#============================================================================Forms=================================================================#
# specify login form
class LoginForm(Form):
    email = StringField('', [validators.Length(min=6, max=40)])  
    password = StringField('', [validators.Length(min=6, max=25)])

# specify add account form
class AddAccountForm(Form):
    email = StringField('', [validators.Length(min=6, max=40)])  
    firstname = StringField('', [validators.Length(min=2, max=25)])
    lastname = StringField('', [validators.Length(min=2, max=25)])
    staffType = SelectField('',choices=[('admin', 'admin'), ('normal', 'normal')])
    password = StringField('', [validators.Length(min=6, max=25)])

# specify edit account form
class EditAccountForm(Form):
    email = StringField('', [validators.Length(min=6, max=40)])  
    firstname = StringField('', [validators.Length(min=2, max=25)])
    lastname = StringField('', [validators.Length(min=2, max=25)])
    staffType = SelectField('',choices=[('admin', 'admin'), ('normal', 'normal')])
    password = StringField('', [validators.Length(min=6, max=25)]) 

# specify add medicine form
class MedicineForm(Form):
    medicineName = StringField('', [validators.Length(min=2, max=25)])

# specify add mmp record form
class MmpRecordForm(Form):
    medicineName = StringField('', [validators.Length(min=2, max=25)])
    dose = StringField('', [validators.Length(min=2, max=25)])
    route = SelectField('',choices=[('INH', 'INH'), ('NEB', 'NEB'), ('PO', 'PO'), 
                                    ('PV', 'PV'), ('PR', 'PR'), ('IV', 'IV'), 
                                    ('IM', 'IM'), ('Subcut', 'Subcut'), ('NG', 'NG'), 
                                    ('REY', 'REY'), ('LEY', 'LEY'), ('BEY', 'BEY'), 
                                    ('Subling', 'Subling'), ('Buccal', 'Buccal'), ('IP', 'IP'), 
                                    ('Epidural', 'Epidural'), ('Intrathecal', 'Intrathecal'), ('Nasal', 'Nasal'), 
                                    ('PEG', 'PEG'), ('Topical', 'Topical')])
    frequency = SelectField('',choices=[('Alternate days', 'Alternate days'), ('BD', 'BD'), ('MANE', 'MANE'), 
                                    ('NOCTE', 'NOCTE'), ('PRN', 'PRN'), ('QID', 'QID'), 
                                    ('Q4h', 'Q4h'), ('Q1H', 'Q1H'), ('Q2H', 'Q2H'), 
                                    ('Q3H', 'Q3H'), ('Q6H', 'Q6H'), ('Q8H', 'Q8H'), 
                                    ('STAT', 'STAT'), ('TDS', 'TDS'), ('Weekly', 'Weekly'), 
                                    ('Midday', 'Midday'), ('Twice weekly', 'Twice weekly')])

# specify mc record form
class McForm(Form):
    dateFrom = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dateTo = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    type = StringField('', [validators.Length(min=2, max=25)])

# specify mc record form
class McRecordForm(Form):
    medicineName = StringField('', [validators.Length(min=2, max=25)])
    date =  DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dose = StringField('', [validators.Length(min=2, max=25)])  
    route = SelectField('',choices=[('INH', 'INH'), ('NEB', 'NEB'), ('PO', 'PO'), 
                                ('PV', 'PV'), ('PR', 'PR'), ('IV', 'IV'), 
                                ('IM', 'IM'), ('Subcut', 'Subcut'), ('NG', 'NG'), 
                                ('REY', 'REY'), ('LEY', 'LEY'), ('BEY', 'BEY'), 
                                ('Subling', 'Subling'), ('Buccal', 'Buccal'), ('IP', 'IP'), 
                                ('Epidural', 'Epidural'), ('Intrathecal', 'Intrathecal'), ('Nasal', 'Nasal'), 
                                ('PEG', 'PEG'), ('Topical', 'Topical')])
    frequency = SelectField('',choices=[('Alternate days', 'Alternate days'), ('BD', 'BD'), ('MANE', 'MANE'), 
                                ('NOCTE', 'NOCTE'), ('PRN', 'PRN'), ('QID', 'QID'), 
                                ('Q4h', 'Q4h'), ('Q1H', 'Q1H'), ('Q2H', 'Q2H'), 
                                ('Q3H', 'Q3H'), ('Q6H', 'Q6H'), ('Q8H', 'Q8H'), 
                                ('STAT', 'STAT'), ('TDS', 'TDS'), ('Weekly', 'Weekly'), 
                                ('Midday', 'Midday'), ('Twice weekly', 'Twice weekly')])

# specify add patient form
class PatientForm(Form):
    urn = StringField('', [validators.Length(min=4, max=10)])  
    firstname = StringField('', [validators.Length(min=2, max=25)])
    lastname = StringField('', [validators.Length(min=2, max=25)])
    dateOfBirth = DateField('')

# specify edit admission form
class AdmissionForm(Form):
    dateFrom = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dateTo = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])

# specify search patient form
class SearchURN(Form):
    urn = StringField('', [validators.Length(min=4, max=10)])  

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)

