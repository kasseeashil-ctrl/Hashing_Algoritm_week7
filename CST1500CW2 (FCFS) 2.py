"""
First-Come-First-Served (FCFS) CPU Scheduling Algorithm.
It is a Simple queue-based scheduling where processes execute in arrival order.
"""

def fcfs_scheduling():
    """
    Interactive FCFS scheduler that takes user input and calculates scheduling metrics
    """
    # Get number of processes from user.
    n = int(input("Enter the number of processes: "))

    # Storage for process data.
    processes = []      # Process IDs
    burst_time = []     # CPU time required by each process

    # Collect process information from the user
    print("\nEnter Process Number and Burst Time for each process:")
    for i in range(n):
        print(f"Process {i + 1}:")
        p_num = int(input("  Process Number: "))
        bt = int(input("  Burst Time: "))
        processes.append(p_num)
        burst_time.append(bt)
        print()

    # Initialise arrays for calculated metrics.
    waiting_time = [0] * n          # Time each process waits before execution
    turnaround_time = [0] * n       # Total time from arrival to completion

    # LOGIC: First process always has 0 waiting time in FCFS
    # Since it's at the front of the queue, it starts immediately.
    waiting_time[0] = 0

    # Calculate waiting time for each subsequent process
    # LOGIC: In FCFS, waiting time = sum of all previous processes' burst times
    # Process i waits for all processes 0 to i-1 to complete
    for i in range(1, n):
        # Current process waits for:
        #Previous process's burst time PLUS
        #Previous process's waiting time (which includes all earlier processes).
        waiting_time[i] = burst_time[i - 1] + waiting_time[i - 1]

    # Calculate turnaround time for each process
    # LOGIC behind : Turnaround time = Time spent in system from arrival to completion
    # For FCFS with all processes arriving at time 0:
    # Turnaround Time = Burst Time + Waiting Time
    for i in range(n):
        turnaround_time[i] = burst_time[i] + waiting_time[i]

    # Calculate average performance metrics
    # LOGIC behind : Average = Sum of all values divided by Number of processes.
    # These metrics help evaluate overall scheduler performance.
    avg_waiting_time = sum(waiting_time) / n
    avg_turnaround_time = sum(turnaround_time) / n

    # Display comprehensive results.
    print("\n" + "=" * 60)
    print("FIRST COME FIRST SERVED (FCFS) SCHEDULING ALGORITHM")
    print("=" * 60)
    # Create table headers with left,aligned columns using fixed widths for clean formatting.
    # <15, <12, <13, <16 set minimum column widths and left,align the text in each column.
    print(f"{'Process Number':<15} {'Burst Time':<12} {'Waiting Time':<13} {'Turn Around Time':<16}")
    print("-" * 60)

    # Display individual process metrics
    for i in range(n):
        print(f"{processes[i]:<15} {burst_time[i]:<12} {waiting_time[i]:<13} {turnaround_time[i]:<16}")

    # Display summary statistics
    print("-" * 60)
    print(f"{'Average':<15} {'':<12} {avg_waiting_time:<13.2f} {avg_turnaround_time:<16.2f}")
    print("=" * 60)


def fcfs_with_default():
    """
    Demonstrates FCFS scheduling using predefined test data given.
    Processes: 1, 2, 3 with Burst Times: 5, 8, 12
    """
    # Test data for demonstration
    processes = [1, 2, 3]
    burst_time = [5, 8, 12]
    n = len(processes)

    # Initialise metric arrays
    waiting_time = [0] * n
    turnaround_time = [0] * n

    # LOGIC:First process starts immediately at time 0
    waiting_time[0] = 0

    # Calculate waiting times using FCFS principle
    # Process 2 waits for Process 1 (5 units)
    # Process 3 waits for Process 1 + Process 2 (5 + 8 = 13 units)
    for i in range(1, n):
        waiting_time[i] = burst_time[i - 1] + waiting_time[i - 1]

    # Calculate turnaround times
    # LOGIC behind: Turnaround = Burst + Waiting
    # Process 1: 5 + 0 = 5
    # Process 2: 8 + 5 = 13
    # Process 3: 12 + 13 = 25
    for i in range(n):
        turnaround_time[i] = burst_time[i] + waiting_time[i]

    # Calculate average performance metrics
    avg_waiting_time = sum(waiting_time) / n
    avg_turnaround_time = sum(turnaround_time) / n

    # Displaying the results
    print("\n" + "=" * 60)
    print("FIRST COME FIRST SERVED (FCFS) - DEFAULT INPUT")
    print("=" * 60)
    print(f"{'Process Number':<15} {'Burst Time':<12} {'Waiting Time':<13} {'Turn Around Time':<16}")
    print("-" * 60)

    for i in range(n):
        print(f"{processes[i]:<15} {burst_time[i]:<12} {waiting_time[i]:<13} {turnaround_time[i]:<16}")

    print("-" * 60)
    # Show averages with proper column alignment, formatting numbers to 2 decimal places
    print(f"{'Average':<15} {'':<12} {avg_waiting_time:<13.2f} {avg_turnaround_time:<16.2f}")
    print("=" * 60)


def main():

    # Main controller function providing user interface.

    print("FIRST COME FIRST SERVED (FCFS) CPU SCHEDULING ALGORITHM")
    print("\nChoose an option:")
    print("1. Use default input (Processes 1, 2, 3 with Burst Times 5, 8, 12)")
    print("2. Enter custom input")

    choice = input("\nEnter your choice (1 or 2): ")

    # path to appropriate function based on user choice
    if choice == '1':
        fcfs_with_default()
    elif choice == '2':
        fcfs_scheduling()
    else:
        # Default fallback if an invalid input is entered.
        print("Invalid choice! Using default input.")
        fcfs_with_default()


# Program entry point, runs main() only when file is executed directly.
if __name__ == "__main__":
    main()