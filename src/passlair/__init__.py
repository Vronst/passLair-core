import logging

# Library convention: don't configure handlers here, just make sure logging
# calls never crash for consumers who haven't set up logging themselves.
logging.getLogger(__name__).addHandler(logging.NullHandler())
