# SPDX-FileCopyrightText: © 2020 Kushal Das <mail@kushaldas.in>
# SPDX-License-Identifier: LGPL-3.0-or-later

__all__ = ["KeyNotFoundError", "FetchingError"]

class KeyNotFoundError(Exception):
    pass


class FetchingError(Exception):
    pass
