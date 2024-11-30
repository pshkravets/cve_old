from datetime import datetime, timedelta

from fastapi import FastAPI, APIRouter, status, HTTPException
from fastapi.responses import JSONResponse

from utils import make_request

app = FastAPI(debug=True)

router = APIRouter()


@router.get('/info/')
def info():
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            '/get/all/': 'Вертає 20 cve Робить запит на NIST вказуючи початкову '
                         'і кінцеву дату та пагінацію на 20 елементів',
            '/get/new/': 'Робить запит на NIST що повертає CVE за останні 24год та вибирає з списку останні 5 '
                         '(якщо розумію правильно бо не міг нормльно протестити через те що один запит обробляється'
                         ' декілька хвилин це якщо буде респонс)',

            '/get/critical/': 'Робить запит на NIST вказуючи параметр cvssV3Severity=CRITICAL',
            '/get': 'Робить запит на NIST який буде шукати CVE з заданим ключовим словом',
            'author': 'Кравець Павло (pashkevuchpasha@gmail.com)',
            'P.S.': 'Ендпоінти на NIST працюють просто ужасно, та часто вертає помилку, тому якщо таке стається то '
                    'робіть запит ще раз з деяким делеєм тому що якщо часто робити воно буде '
                    'повертати 403 (походу обмеження на запроси для захисту від DDOS). Не придумав як пофіксити можливо'
                    'б апі ключ допоміг але не став пробувати... Гарного перегляду завдання:)'
        }
    )


@router.get('/get/all/')
def all():
    current_date = datetime.now()
    start_date = current_date - timedelta(days=5)
    params = {
        'pubStartDate': start_date.isoformat(),
        'pubEndDate': current_date.isoformat(),
        'resultsPerPage': 20,
        'startIndex': 0
    }
    response = make_request(params)
    try:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'vulnerabilities': response.json()['vulnerabilities']}
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='NIST endpoint doesn\'t work try again:)'
        )


@router.get('/get/new/')
def new():
    current_date = datetime.now()
    start_date = current_date - timedelta(days=1)
    params = {
        'pubStartDate': start_date.isoformat(),
        'pubEndDate': current_date.isoformat(),
        'startIndex': 0
    }
    response = make_request(params)
    try:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'vulnerabilities': response.json()['vulnerabilities'][-5:]}
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='NIST endpoint doesn\'t work try again:)'
        )


@router.get('/get/critical/')
def critical():
    params = {
        'resultsPerPage': 10,
        'startIndex': 0,
        'cvssV3Severity': 'CRITICAL'
    }
    response = make_request(params)
    try:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'vulnerabilities': response.json()['vulnerabilities']}
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='NIST endpoint doesn\'t work try again:)'
        )


@router.get('/get')
def keyword(query):
    params = {
        'keywordSearch': query
    }
    response = make_request(params)
    try:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={'vulnerabilities': response.json()['vulnerabilities']}
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='NIST endpoint doesn\'t work try again:)'
        )


app.include_router(router)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)