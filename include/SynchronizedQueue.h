#include <queue>
#include <condition_variable>

template <typename T> class SynchronizedQueue
{
        std::queue<T> queue_;
        std::mutex mutex_;
        std::condition_variable condvar_;

        typedef std::lock_guard<std::mutex> lock;
        typedef std::unique_lock<std::mutex> ulock;

    public:

        ~SynchronizedQueue()
        {
            condvar_.notify_all();
        }

        void push(T const &val)
        {
            lock l(mutex_); // prevents multiple pushes corrupting queue_
            bool wake = queue_.empty(); // we may need to wake consumer
            queue_.push(val);
            if (wake) condvar_.notify_one();
        }

        T pop()
        {
            ulock u(mutex_);
            if (queue_.empty())
                condvar_.wait(u);
            if (queue_.empty())
                throw 200;
            // now queue_ is non-empty and we still have the lock
            T retval = queue_.front();
            queue_.pop();
            return retval;
        }

        void close()
        {
            condvar_.notify_one();
        }
};