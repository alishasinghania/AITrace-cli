from build import make_query


def run(request):
    cursor.execute(make_query(request))  # gt:sql:sql_interpolation
