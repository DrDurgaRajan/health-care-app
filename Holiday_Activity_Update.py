import os
import time
import bcrypt
import sqlite3
import datetime
import PySimpleGUI as sg
from tabulate import tabulate


def Db_connexion(db):
    try:
        connexion = sqlite3.connect(db)
    finally:
        connexion.close()

def Create_table(db):
    connexion = sqlite3.connect(db)
    cursor = connexion.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Bookings(
                    Reference INT PRIMARY KEY,
                    Date TEXT,
                    Hour TEXT,
                    Student_ID INT,
                    Student_Name TEXT,
                    College TEXT,
                    Team TEXT,
                    Extra_Activities TEXT,
                    Total_Amount__£ INT 
                    ) 
                    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Logins(
                    Reference INT PRIMARY KEY,
                    Staff_ID INT,
                    Staff_Name TEXT,
                    Password TEXT,
                    Access_Control TEXT
                    ) 
                    """)
    connexion.close()

def Booking_References():
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    cursor.execute(' SELECT EXISTS( SELECT 1 FROM Bookings LIMIT 1)' )
    result = cursor.fetchone()
    if result[0] == 0:
        connexion.close()
        return 0
    else:
        ref = cursor.execute('SELECT * FROM Bookings WHERE ROWID IN (SELECT max(ROWID) FROM Bookings) ').fetchone()
        ref = ref[0]
        connexion.close()
        return int(ref)

def Staff_References():
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    cursor.execute(' SELECT EXISTS( SELECT 1 FROM Logins LIMIT 1)' )
    result = cursor.fetchone()
    if result[0] == 0:
        connexion.close()
        return 0
    else:
        ref = cursor.execute('SELECT * FROM Logins WHERE ROWID IN (SELECT max(ROWID) FROM Logins) ').fetchone()
        ref = ref[0]
        connexion.close()
        return int(ref)

def Login_data():
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    cursor.execute(" SELECT * FROM Logins ")
    data =  cursor.fetchall()
    connexion.close()
    return data


Db_connexion('Booking_data.db')
Create_table('Booking_data.db')

Booking_references = Booking_References()
Staff_references   = Staff_References()

LOGIN = Login_data()


total = 0

colleges        = ['Westminster (£ 350)', 'Tottenham (£ 300)', 'Enfield (£ 275)' ]
price_colleges  = [350, 300, 275]

teams       = ['Gold(£ 25)', 'Amber (£ 15)', 'Silver (£ 20)', 'Bronze (£ 10)']
price_teams = [25, 15, 20, 10]

parameter = ['Adding ', 'Removing', 'Modifying']

role      = ['Administrator', 'Staff', 'Client']


extra_activities = {'Canoeing': 35, 'Hiking': 25}

message         = None

Username = sg.Text('Username'), sg.InputText(key = '-USERNAME-', size = (15, 1))
Password = sg.Text('Password'), sg.InputText(key = '-PASSWORD-', password_char = '*', size = (15, 1))
Col_Tb1  = sg.Column([[sg.Text('Booking Activities'), sg.Text(f'Total Amount {total} ', key = '-AMOUNT-', justification = 'right')]])
Col1     = sg.Column([[sg.Text('Holidays Activities'), sg.Text ('', key ='date'), sg.Text ('', key ='clock')]])
Col2_Tb1 = sg.Column([[sg.Text("Student ID      "), sg.Input(key="-ID-", size = (15, 1)), sg.Combo(values =colleges, key = '-COLLEGE-', enable_events = True, default_value = 'Colleges', readonly = True)]])
Col3_Tb1 = sg.Column([[sg.Text("Student Name "), sg.Input(key="-NAME-", size = (15, 1)) , sg.Combo(values =teams, key = '-TEAM-', enable_events = True, default_value = 'Teams', readonly = True)]])


Col_Tb3  = sg.Column([[sg.Text('Managing Staff', key = '-REF-' )]])
Col4_Tb3 = sg.Column([[sg.Text("Staff ID         "), sg.Input(key="-STAFF_ID-", size = (15, 1)), sg.Combo(values = role, key = '-ACCESS-', enable_events = True, default_value = 'Access type', readonly = True)]])
Col5_Tb3 = sg.Column([[sg.Text("Staff Name    "),    sg.Input(key="-STAFF_NAME-", size = (15, 1)), sg.Combo(values = parameter, key = '-PARAMETER-', enable_events = True, default_value = 'Parameter', readonly = True) ]])
Col6_Tb3 = sg.Column([[sg.Text("Password      "),    sg.Input(key = '-PASSWORDS-', size = (15, 1), password_char = '*')]])
Col7_Tb3 = sg.Column([[sg.Text(f"{message}", key = '-MSG-'),      sg.Input(key = '-CONFIRMATION-', size = (15, 1), password_char = '*'), sg.Button('Confirm')]])

checkboxes = [sg.Checkbox(f"{activitie} (£ {price})", key = activitie) for activitie, price in extra_activities.items()]

error_name      = 'The name must contains Alphabetic characters like A-Z or a-z.'
error_id        = 'The Id must contain 6 digits number not null.'
error_college   = 'You must choice a college'
error_team      = 'You must choice a teams' 
error_access    = 'You must choice a Access type'
error_parameter = 'You must choice a Parameter'
error_password  = 'A strong Password must containt at list (8 Caracter, 1 Uppercase and 1 Number)'
error_matching  = 'Your Password and Confirmation must be same'
invalid_loging  = 'Your Password is Incorrect'
 

Tab1 = [
    [Col_Tb1],
    [Col2_Tb1],
    [Col3_Tb1],
    checkboxes,
    [sg.Button('Submit')]
    ]

Tab2 = [
    [sg.Text('Booking Stories')],
    [sg.Button('See Booking History')],
    [sg.Button('See Staff Login')]
    ]

Tab3 = [
    [Col_Tb3],
    [Col4_Tb3],
    [Col5_Tb3],
    [Col6_Tb3],
    [Col7_Tb3]
    ]

tabband = [
    [
         sg.Tab('Booking Activities', Tab1, key = '-tab1-'),
         sg.Tab('Booking Stories', Tab2, key = '-tab2-'),
         sg.Tab('Managing Staff', Tab3, key = '-tab3-')
            
        ]
    ]

layout = [
    [Col1],
    [sg.TabGroup(tabband, key = '-TABGROUP-' )],
    [sg.Column([[sg.Button('Exit'), sg.Text('Detail Users', key = '-USER-')]])]
    ]

def Login_layout():
    layout = [
        [sg.Text('Staff Log In', justification = "center", size = (25, 1))],
        [Username],
        [Password],
        [sg.Button('Log In'), sg.Button('Exit')]
        ]
    return layout
    
login  = sg.Window('Login', Login_layout())


def loging(username, password):
    for login in LOGIN:
        if username == login[1]:
            if Dehashing_Password(password, login[3]) is True:
                return True
            else:
                check_login = False
        else:
            check_login = False
    return check_login

def User_Detail_Access(username, password):
    for login in LOGIN:
        if username == login[1]:
            if Dehashing_Password(password, login[3]) is True:
                break
    if login[4] == 'Administrator':
        role = ['Administrator', 'Staff', 'Client']
    elif login[4] == 'Staff':
        role = ['Staff', 'Client']
    else:
        role = []

    return login, role

def Hashing_Password(password):
    password = password.encode('utf-8')
    sel = bcrypt.gensalt()

    return bcrypt.hashpw(password, sel)

def Dehashing_Password(password, password_hashed):
    password = password.encode('utf-8')

    if bcrypt.checkpw(password, password_hashed):
        return True
    else:
        return False
    

def checkError_id(user_input):
    if user_input.isdigit() and len(user_input) == 6 and int(user_input) > 0:
        return True
    else:
        return False

def checkError_name(user_input):
    while True:
        if "".join(user_input.split()).isalpha() == True:
            return True
        else:
            return False

def checkError_password(password):
    if len(password) >= 8:
        content_number = any(caractere.isdigit() for caractere in password)
        content_upper  = any(caractere.isupper() for caractere in password)
        content_lower  = any(caractere.islower() for caractere in password)
        validity_check = content_number * content_upper * content_lower
        if validity_check == 1:
            return True
        else:
            return False  
    else:
        return False


def Error_Booking():
    error = True 
    if checkError_name(booking['Student_Name']) is False:
        error *= checkError_name(booking['Student_Name'])
        sg.popup(error_name, title = 'Error Student Name')

    if checkError_id(booking['Student_Id']) is False:
        error *= checkError_id(booking['Student_Id'])
        sg.popup(error_id, title = 'Error Student Id')

    if booking['College'] == 'Colleges':
        error *= False
        sg.popup(error_college, title = 'Error College')

    if booking['Team'] == 'Teams':
        error *= False
        sg.popup(error_team, title = 'Error Teams')

    return error


def Error_Staff():
    error = True 
    if checkError_name(Adding_Staff['Staff_Name']) is False:
        error *= checkError_name(Adding_Staff['Staff_Name'])
        sg.popup(error_name, title = 'Error Staff Name')

    if checkError_id(Adding_Staff['Staff_Id']) is False:
        error *= checkError_id(Adding_Staff['Staff_Id'])
        sg.popup(error_id, title = 'Error Staff Id')

    if Adding_Staff['Access_Control'] == 'Access type':
        error *= False
        sg.popup(error_access, title = 'Error Access type')

    if Adding_Staff['Parameter'] == 'Parameter':
        error *= False
        sg.popup(error_parameter, title = 'Error Parameter')

    if checkError_password(Adding_Staff['Staff_Password']) is False:
        error *= False
        sg.popup(error_password, title = 'Error Password')
        
    if Adding_Staff['Staff_Password'] != Adding_Staff['Staff_Confirmation']:
        if Adding_Staff['Parameter'] != 'Modifying':
            error *= False
            sg.popup(error_matching, title = 'Error Matching')

    return error
    
    

def Total_amount():
    booking['Total_amount (£)'] = Extra_activities()
    if booking['College'] in colleges:
        booking['Total_amount (£)'] += College()
    if booking['Team'] in teams:
        booking['Total_amount (£)'] += Team()
    total = booking['Total_amount (£)']
        
    return total

        
def Refresh_Booking():
    window['-ID-'].update('')
    window['-NAME-'].update('')
    window['-COLLEGE-'].update(value = 'Colleges')
    window['-TEAM-'].update(value = 'Teams')
    window['Canoeing'].update(value = False)
    window['Hiking'].update(value = False)
    
def Refresh_Staff_Adding():
    window['-STAFF_ID-'].update('')
    window['-STAFF_NAME-'].update('')
    window['-PASSWORDS-'].update('')
    window['-CONFIRMATION-'].update('')
    window['-ACCESS-'].update(value = 'Access type')
    window['-PARAMETER-'].update(value = 'Parameter')
    window['Canoeing'].update(value = False)
    window['Hiking'].update(value = False)


def College():
    college = values['-COLLEGE-']
    if college:
        index = colleges.index(college)
        return  price_colleges[index]
        
def Team():
    team = values['-TEAM-']
    if team:
        index = teams.index(team)
        return  price_teams[index]

def Extra_activities():
    total = 0
    booking['Extra_activities'] = ''
    for activitie, price in extra_activities.items():
        if values[activitie]:
            if len(booking['Extra_activities']) > 0:
                booking['Extra_activities'] += ', ' + activitie
            else:   
                booking['Extra_activities'] = activitie
            total += price
    if total == 0:
        booking['Extra_activities'] = 'None'
        
    return total

    

def See_booking():
    print("Reference        :",   booking['Reference'])
    print("Date             :",   booking['Date'])
    print("Hour             :",   booking['Hour'])
    print("Name             :",   booking['Student_Name'])
    print("Id               :",   booking['Student_Id'])
    print("Centre           :",   booking['College'])
    print("Team             :",   booking['Team'])
    print("Extra Activities :",   booking['Extra_activities'])
    print("Total Amount     : £", booking['Total_amount (£)'])

def See_staff_added():
    print("Reference        :",   Adding_Staff['Reference'])
    print("Name             :",   Adding_Staff['Staff_Name'])
    print("Id               :",   Adding_Staff['Staff_Id'])
    print("Password         :",   Adding_Staff['Staff_Password'])
    print("Confirmation     :",   Adding_Staff['Staff_Confirmation'])
    print("Access Control   :",   Adding_Staff['Access_Control'])
    print("Parameter        :",   Adding_Staff['Parameter'])

def Tab1_booking():
    global booking
    booking = {
        'Reference'        : Booking_references + 1,
        'Date'             : str(date),
        'Hour'             : str(hour), 
        'College'          : values['-COLLEGE-'],
        'Student_Id'       : values['-ID-'], 
        'Student_Name'     : values['-NAME-'].title(),
        'Team'             : values['-TEAM-'],
        'Extra_activities' : None,
        'Total_amount (£)' : 0
        }

def Tab3_staff():
    global Adding_Staff
    Adding_Staff = {
        'Reference'          : Staff_references + 1,
        'Staff_Id'           : values['-STAFF_ID-'], 
        'Staff_Name'         : values['-STAFF_NAME-'].title(),
        'Staff_Password'     : values['-PASSWORDS-'],
        'Staff_Confirmation' : values['-CONFIRMATION-'],
        'Access_Control'     : values['-ACCESS-'],
        'Parameter'          : values['-PARAMETER-']
        }

def Password_Modification(cursor):
    invalid_detail  = f"The Staff With ID '{Adding_Staff['Staff_Id']}' and Password '{Adding_Staff['Staff_Password']}' Not Found"
    if loging(int(values['-STAFF_ID-']), values['-PASSWORDS-'] ) is False:
        sg.popup(invalid_detail, title = "Modification error")
    else:
        if checkError_password(Adding_Staff['Staff_Confirmation']) is False:
            sg.popup(error_password, title = 'Error Password')
        else:
            cursor.execute("UPDATE Logins SET Password = ? WHERE Staff_ID = ?", (Hashing_Password(Adding_Staff['Staff_Confirmation']), Adding_Staff['Staff_Id'], ) )
            Refresh_Staff_Adding()
            See_staff_added()
            
def Login_Deletion(cursor):
    invalid_detail  = f"The Staff With ID '{Adding_Staff['Staff_Id']}' and Password '{Adding_Staff['Staff_Password']}' Not Found"
    if loging(int(values['-STAFF_ID-']), values['-PASSWORDS-'] ) is False:
        sg.popup(invalid_detail, title = "Information error")
    else:
        if Error_Staff() == 1:
            cursor.execute("DELETE FROM Logins WHERE Staff_ID = ? ", (int(Adding_Staff['Staff_Id']), ))
            Refresh_Staff_Adding()
            See_staff_added()

def Tab1_submission():
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    cursor.execute(" INSERT INTO Bookings( Reference, Date, Hour, Student_ID, Student_Name, College, Team, Extra_Activities, Total_Amount__£  ) VALUES ( ? , ?, ? , ?, ? , ?, ? , ?, ?)",(booking['Reference'], booking['Date'], booking['Hour'], booking['Student_Id'], booking['Student_Name'],  booking['College'], booking['Team'], booking['Extra_activities'], booking['Total_amount (£)']) )
    connexion.commit()
    connexion.close()
    See_booking()
    Refresh_Booking()

def Tab3_submission():
    ref = 0
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    if Adding_Staff['Parameter'] == 'Adding ':
        cursor.execute(" INSERT INTO Logins( Reference, Staff_ID, Staff_Name, Password, Access_Control  ) VALUES ( ? , ?, ?, ?, ? )",(Adding_Staff['Reference'], Adding_Staff['Staff_Id'], Adding_Staff['Staff_Name'], Hashing_Password(Adding_Staff['Staff_Password']), Adding_Staff['Access_Control']) )
        ref = 1
        Refresh_Staff_Adding()
        See_staff_added()
    elif Adding_Staff['Parameter'] == 'Removing':
        Login_Deletion(cursor)
    else:
        Password_Modification(cursor)

    connexion.commit()
    connexion.close()
    LOGIN = Login_data()
    return ref

def Tab2_See_Booking_history():
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    cursor.execute(" SELECT * FROM Bookings ")
    history = cursor.fetchall()
    connexion.close()
    headers = ['Reference', 'Date', 'Hour', 'Student ID', 'Student Name', 'College', 'Team', 'Extra Activities', 'Total Amount £'  ]
    print(tabulate(history, headers , tablefmt = 'fancy_grid'))

def Tab2_See_Staff():
    connexion = sqlite3.connect('Booking_data.db')
    cursor = connexion.cursor()
    cursor.execute(" SELECT * FROM Logins ")
    history = cursor.fetchall()
    connexion.close()
    headers = ['Reference', 'Staff ID', 'Staff Name', 'Password', 'Statut', ]
    print(tabulate(history, headers , tablefmt = 'fancy_grid'))



while True:
    event, values = login.read()
    username = values['-USERNAME-']
    password = values['-PASSWORD-']

    if event =='Exit' or event == sg.WIN_CLOSED:
        break
    else:
        if not username.isdigit() or loging(int(username), password) is False:
            sg.popup(invalid_loging, title = 'Invalid Loging')
            login['-USERNAME-'].update('')
            login['-PASSWORD-'].update('')  
        else:
            login.close()
            Access = True
            Login, role = User_Detail_Access(int(username), password)
            window = sg.Window('Tier Tec Program', layout)
            while True:
                event, values = window.read(timeout = 1000)
                date = datetime.date.today()
                hour = time.strftime('%H: %M: %S')
                print = sg.Print
                
                window['date'].update(date.strftime('%A %d: %m: %Y'))
                window['clock'].update(time.strftime('%H: %M: %S'))
                window['-AMOUNT-'].update(f' N* Reference {Booking_references + 1}            Total Amount {total}')
                window['-REF-'].update(f' Managing Staff             N* Reference {Staff_references + 1}')
                window['-MSG-'].update(f'{message}  ')
                if Access:
                    window['-USER-'].update(f" User Connected '{Login[2]}', Id '{Login[1]}', Statut '{Login[4]}'")
                    window['-ACCESS-'].update(values = role, value = 'Access type')
                    Access = False
                
                if values is not None:
                    Tab_name = values['-TABGROUP-']

                if Tab_name == '-tab1-':
                    Tab1_booking()
                    total = Total_amount()

                    if event == 'Submit': 
                        if Error_Booking() == 1:
                            Tab1_submission()
                            Booking_references += 1

                if Tab_name == '-tab2-':
                    if event == 'See Booking History':
                        Tab2_See_Booking_history()
                    elif event == 'See Staff Login':
                        Tab2_See_Staff()
                    

                if Tab_name == '-tab3-':
                    Tab3_staff()

                    if Adding_Staff['Parameter'] != 'Modifying':
                        message = "Confirmation"
                    else:
                        message = "New Password"
                    
                    if event == 'Confirm': 
                        if Error_Staff() == 1:
                            Staff_references += Tab3_submission()

                if event =='Exit' or event == sg.WIN_CLOSED:
                    break

            window.close()
        

login.close()




