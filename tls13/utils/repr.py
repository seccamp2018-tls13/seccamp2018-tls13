
import inspect
import textwrap
import pprint
from .type import Uint, Type

def make_format(obj, props):
    repr_str = ""
    repr_str += "%s:\n" % obj.__class__.__name__
    for prop, prop_type in list(props.items()):
        item = getattr(obj, prop)
        item_len = len(item)

        assert inspect.isclass(prop_type)

        if prop_type in (str, bytes, bytearray):
            if item_len > 15:
                item = item[0:10].hex() + '...'
            else:
                item = item.hex()
            repr_str += "|%s: %s (len=%d)\n" % (prop, item, item_len)
        elif prop_type == list and all(isinstance(x, Uint) for x in item):
            repr_str += "|%s: %s\n" % (prop, item)
        elif prop_type in (list, object):
            repr_str += "|%s:\n" % prop
            repr_str += textwrap.indent(pprint.pformat(item), prefix="    ")
            if prop_type == list: repr_str += "\n"
        elif issubclass(prop_type, Type):
            const_name = prop_type.labels[item]
            repr_str += "|%s: %s == %s\n" % (prop, item, const_name)
        elif prop_type == int and isinstance(item, Uint):
            repr_str += "|%s: %s == %s\n" % (prop, getattr(obj, prop), int(item))
        else:
            repr_str += "|%s: %s\n" % (prop, getattr(obj, prop))

    return repr_str.strip()
