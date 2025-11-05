@echo off
title Analisador de Malware - Servidor de Producao

echo =================================================================
echo  Analisador de Malware - Servidor de Producao (Waitress)
echo =================================================================
echo.

REM Navega para o diretorio onde o script .bat esta localizado
cd /d "%~dp0"

echo Ativando o ambiente virtual (venv)...
call venv\Scripts\activate

echo.
echo Iniciando o servidor de producao com Waitress...
echo O servidor estara disponivel em http://localhost:5000 ou http://SEU_IP_LOCAL:5000
echo Pressione Ctrl+C para parar o servidor.
echo.

waitress-serve --host=0.0.0.0 --port=5000 app.analisador_malware:app

pause