import matplotlib.pyplot as plt

# Read the signal data from signal.txt
with open('signal.txt', 'r') as file:
    signal_data = eval(file.read())


# stats
print("-5:",signal_data.count(-5))
print("-3:",signal_data.count(-3))
print("-1:",signal_data.count(-1))
print("1:",signal_data.count(1))
print("3:",signal_data.count(3))
print("5:",signal_data.count(5))



# Create a time axis (assuming one data point per unit of time)
time_axis = range(len(signal_data[:50]))

# Plot the signal
plt.plot(time_axis, signal_data[:50], marker='o', linestyle='-', color='b')
plt.title('Signal Plot')
plt.xlabel('Time')
plt.ylabel('Amplitude')
plt.grid(True)
plt.show()