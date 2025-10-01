"""Enhanced thread pool management for liffy"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from .rich_output import print_info, print_error, print_success


class ThreadManager:
    """Enhanced thread pool manager with rate limiting and monitoring"""

    def __init__(self, max_workers=5, rate_limit_delay=0.1):
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.active_threads = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        self.start_time = None
        self.lock = threading.Lock()

    def execute_tasks(self, tasks, task_args_list):
        """Execute a list of tasks with enhanced monitoring"""
        self.start_time = time.time()
        total_tasks = len(tasks) * len(task_args_list) if task_args_list else len(tasks)

        print_info(f"Starting {total_tasks} tasks with {self.max_workers} workers")

        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {}

            if task_args_list:
                # Multiple args for each task
                for task in tasks:
                    for args in task_args_list:
                        future = executor.submit(
                            self._execute_with_monitoring, task, args
                        )
                        future_to_task[future] = (task, args)
            else:
                # Single execution for each task
                for task in tasks:
                    future = executor.submit(self._execute_with_monitoring, task)
                    future_to_task[future] = (task, None)

            # Process completed tasks
            for future in as_completed(future_to_task):
                task_info = future_to_task[future]
                try:
                    result = future.result()
                    results.append(result)
                    with self.lock:
                        self.completed_tasks += 1
                except Exception as exc:
                    with self.lock:
                        self.failed_tasks += 1
                    print_error(
                        f"Task {task_info[0].__name__} generated exception: {exc}"
                    )

                # Progress reporting
                self._report_progress(total_tasks)

        self._final_report()
        return results

    def _execute_with_monitoring(self, task, args=None):
        """Execute a single task with monitoring and rate limiting"""
        with self.lock:
            self.active_threads += 1

        try:
            # Apply rate limiting
            if self.rate_limit_delay > 0:
                time.sleep(self.rate_limit_delay)

            # Execute the task
            if args:
                return task(args)
            else:
                return task()

        finally:
            with self.lock:
                self.active_threads -= 1

    def _report_progress(self, total_tasks):
        """Report progress periodically"""
        completed = self.completed_tasks + self.failed_tasks
        if completed % max(1, total_tasks // 10) == 0 or completed == total_tasks:
            progress = (completed / total_tasks) * 100
            elapsed = time.time() - self.start_time
            print_info(
                f"Progress: {completed}/{total_tasks} ({progress:.1f}%) - {elapsed:.1f}s elapsed"
            )

    def _final_report(self):
        """Print final execution report"""
        elapsed = time.time() - self.start_time
        total_tasks = self.completed_tasks + self.failed_tasks

        print_success(f"Thread execution completed in {elapsed:.2f}s")
        print_info(f"Completed: {self.completed_tasks}, Failed: {self.failed_tasks}")

        if total_tasks > 0:
            success_rate = (self.completed_tasks / total_tasks) * 100
            print_info(f"Success rate: {success_rate:.1f}%")
            print_info(f"Average time per task: {elapsed / total_tasks:.3f}s")


class PayloadQueue:
    """Thread-safe payload queue for coordinated testing"""

    def __init__(self, payloads):
        self.queue = Queue()
        self.results = Queue()
        self.total_payloads = len(payloads)
        self.processed = 0
        self.lock = threading.Lock()

        # Populate queue
        for payload in payloads:
            self.queue.put(payload)

    def get_payload(self, timeout=1):
        """Get next payload from queue"""
        try:
            return self.queue.get(timeout=timeout)
        except Empty:
            return None

    def add_result(self, result):
        """Add result to results queue"""
        self.results.put(result)
        with self.lock:
            self.processed += 1

    def get_results(self):
        """Get all results"""
        results = []
        while not self.results.empty():
            try:
                results.append(self.results.get_nowait())
            except Empty:
                break
        return results

    def is_complete(self):
        """Check if all payloads have been processed"""
        return self.processed >= self.total_payloads


class AdaptiveThreadPool:
    """Adaptive thread pool that adjusts workers based on performance"""

    def __init__(self, initial_workers=3, max_workers=10, min_workers=1):
        self.current_workers = initial_workers
        self.max_workers = max_workers
        self.min_workers = min_workers
        self.performance_history = []
        self.adjustment_interval = 10  # Adjust every N tasks

    def adjust_workers(self, completion_time, error_rate):
        """Adjust number of workers based on performance metrics"""
        self.performance_history.append(
            {
                "workers": self.current_workers,
                "time": completion_time,
                "error_rate": error_rate,
            }
        )

        # Keep only recent history
        if len(self.performance_history) > 20:
            self.performance_history = self.performance_history[-20:]

        # Don't adjust too frequently
        if len(self.performance_history) % self.adjustment_interval != 0:
            return

        # Analyze performance trend
        if len(self.performance_history) >= 2:
            recent = self.performance_history[-1]
            previous = self.performance_history[-2]

            # If error rate is increasing, reduce workers
            if recent["error_rate"] > previous["error_rate"] + 0.1:
                self.current_workers = max(self.min_workers, self.current_workers - 1)
                print_info(
                    f"Reducing workers to {self.current_workers} due to high error rate"
                )

            # If performance is good and we have capacity, increase workers
            elif (
                recent["error_rate"] < 0.1
                and recent["time"] < previous["time"]
                and self.current_workers < self.max_workers
            ):
                self.current_workers = min(self.max_workers, self.current_workers + 1)
                print_info(
                    f"Increasing workers to {self.current_workers} for better performance"
                )

    def get_optimal_workers(self):
        """Get current optimal number of workers"""
        return self.current_workers


def create_thread_manager_from_config(config):
    """Create thread manager from configuration"""
    max_workers = config.get("max_threads", 5)
    rate_limit_delay = config.get("rate_limit_delay", 0.1)

    return ThreadManager(max_workers=max_workers, rate_limit_delay=rate_limit_delay)
