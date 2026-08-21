@echo off
title Entrou, Economizou - Gerador Automatico
cd /d "%~dp0"
echo.
echo Iniciando o gerador automatico...
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 app.py
    goto fim
)

where python >nul 2>nul
if %errorlevel%==0 (
    python app.py
    goto fim
)

echo.
echo ================================================================
echo Python nao foi encontrado neste computador.
echo Instale o Python 3 e marque a opcao "Add Python to PATH".
echo Depois execute este arquivo novamente.
echo ================================================================
pause

:fim
