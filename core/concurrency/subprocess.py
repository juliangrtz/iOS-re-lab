from concurrent.futures import ProcessPoolExecutor, Future
from functools import partial
from typing import Callable, Optional, Any


# Used for heavy calculations where a thread is not enough and blocking the UI is not feasible.
class Subprocess:
    def __init__(self):
        self.executor = ProcessPoolExecutor()
        self.future: Optional[Future] = None

    def submit(
            self,
            func: Callable,
            *args,
            on_done: Optional[Callable[[Any], None]] = None,
            on_error: Optional[Callable[[Exception], None]] = None,
            **kwargs
    ):
        if self.future and not self.future.done():
            self.future.cancel()

        self.future = self.executor.submit(func, *args, **kwargs)
        self.future.add_done_callback(
            partial(self._handle_future, on_done=on_done, on_error=on_error)
        )

    def _handle_future(self, future: Future, on_done: Optional[Callable], on_error: Optional[Callable]):
        self._process_future(future, on_done, on_error)

    def _process_future(self, future: Future, on_done: Optional[Callable], on_error: Optional[Callable]):
        try:
            result = future.result()
        except Exception as e:
            if on_error:
                on_error(e)
        else:
            if on_done:
                on_done(result)

    def shutdown(self, wait: bool = False, cancel_futures: bool = True):
        if self.future and not self.future.done():
            self.future.cancel()
        self.executor.shutdown(wait=wait, cancel_futures=cancel_futures)
