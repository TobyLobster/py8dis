"""Penetrator, Stefan Wessels's Apple II remake of the ZX Spectrum game (see
orig/penetrator/README.txt), with load_apple_file() and apple.apple2().

The game is an AppleSingle file, a BIN file at $4000: the title picture
(for hi-res page 2), then the code, from $6000, where its loader runs it,
then its read-only data and variables. apple2() finds the soft switches it
uses (the speaker, the hi-res pages, the keyboard and the paddles), its
calls to the Monitor, and its ProDOS MLI calls, which save and load the
high scores (their parameter lists, pathname buffer and file buffers are
labelled). The game's procedures and zero page variables are named here
from its source (from the label file ld65 makes with -Ln)."""

from commands import *
import apple

start = load_apple_file("orig/penetrator.orig", "6502", "2d44386752659f1c243c331cae0ac984")
assert start == 0x4000
apple.apple2()

# The title picture, which is shown on hi-res page 2
label(0x4000, "logo_picture")
byte(0x4000, 0x2000)

# The game's procedures, from its source
procedures = {
    0x6003: "serviceAudio",
    0x6069: "playNote",
    0x6083: "inputReadJoystick",
    0x60d4: "inputGame",
    0x61a1: "inputEdit",
    0x6268: "inputCheckForInput",
    0x62a5: "uiTitleScreen",
    0x6397: "uiShowHighScores",
    0x6429: "uiWriteName",
    0x6521: "uiMainMenu",
    0x6686: "uiTrainerMode",
    0x66fd: "uiHandleOptions",
    0x672a: "uiShowEditHelp",
    0x6887: "uiWinScreen",
    0x693f: "uiShowGameLabels",
    0x69b6: "uiUpdateGameHud",
    0x6a30: "uiShowEditLabels",
    0x6ac1: "uiCheckHighScore",
    0x6b17: "uiInsertHighScoreRow",
    0x6b50: "uiGetHighScoreName",
    0x6c0d: "uiFileLoadSave",
    0x6d97: "uiGetUserText",
    0x6df0: "editLoop",
    0x6e21: "editHandleKeys",
    0x6e94: "editGameWorldRight",
    0x6ec0: "editGameWorldLeft",
    0x6f2e: "editInit",
    0x6f76: "editDrawCursor",
    0x6fc6: "editSetTerrainBottom",
    0x700e: "editSetTerrainTop",
    0x702f: "editPreSetEnemy",
    0x7079: "editSetRadar",
    0x709a: "editSetMissile",
    0x70bb: "editLoadStage",
    0x70ce: "gamePlay",
    0x716d: "gameInit",
    0x71a0: "gameLevelInit",
    0x7204: "gameShowPlayer",
    0x724d: "gamePlaceShip",
    0x728a: "gameCheckStage",
    0x72c5: "gameAI",
    0x73b0: "gameMonsterAI",
    0x7438: "gameWorldMove",
    0x74ab: "gameFindStage",
    0x750d: "gameUpdateDangerBar",
    0x7536: "gameWorldFlag",
    0x75e3: "gamePlayerCollision",
    0x7609: "gameNextPlayer",
    0x7656: "gameStatsToPlayer",
    0x766a: "gamePlayerToStats",
    0x767e: "gameWinSequence",
    0x76bc: "gameKillEnemy",
    0x7738: "gameAddScore",
    0x776b: "terrainShow",
    0x77dc: "terrainDrawLeftColumn",
    0x789f: "terrainDrawRightColumn",
    0x79e7: "drawPresent",
    0x79ff: "drawClearRows",
    0x7e38: "drawClearScreen",
    0x7f02: "drawInvertVisibleScreen",
    0x7f23: "drawPlotXY",
    0x7f77: "drawSprite",
    0x7fcc: "drawPlayer",
    0x806d: "drawRadar",
    0x80d9: "drawMissile",
    0x8136: "drawNuke",
    0x818e: "drawMonster",
    0x81df: "drawBombs",
    0x8285: "drawBullets",
    0x8357: "drawExplosions",
    0x83d1: "drawEnemies",
    0x843f: "textOut",
    0x847a: "textBigPrint",
    0x84dc: "setFont",
    0x84f9: "textBCDtoSZ",
    0x8547: "toHex",
    0x8561: "saveWorld",
    0x8578: "loadWorld",
    0x858f: "saveHighScores",
    0x85a9: "loadHighScores",
    0x85c3: "setHighScoreFileNames",
    0x85da: "setWorldFileName",
    0x85ef: "saveFile",
    0x861a: "loadFile",
    0x863f: "main",
    0x8656: "mainGameSetup",
}
for addr, name in procedures.items():
    label(addr, name)

# Its zero page variables
zero_page = {
    0x50: "zWorldPtr",
    0x52: "zVramH",
    0x53: "zScreenCol",
    0x54: "zEnemyCol",
    0x55: "zCollision",
    0x56: "tempBlock",
    0x6c: "Bit1Mask",
    0x6d: "Bit2Mask",
    0x6e: "Bit3Mask",
    0x6f: "Bit4Mask",
    0x70: "Bit5Mask",
    0x71: "Bit6Mask",
    0x72: "Bit7Mask",
    0x73: "Bit8Mask",
    0x74: "Bit12Mask",
    0x75: "Bit34Mask",
    0x76: "Bit76Mask",
    0x77: "Bit8432Mask",
    0x78: "Bit8765Mask",
    0x79: "numPlayers",
    0x7a: "activePlayer",
    0x7b: "gameMode",
    0x7c: "playerShipX",
    0x7d: "playerShipY",
    0x7e: "terrainOrigin",
    0x7f: "stopScrolling",
    0x80: "playerDead",
    0x81: "monsterCnt",
    0x82: "inFlight",
    0x84: "victory",
    0x85: "nextStage",
    0x86: "bufferInsert",
    0x87: "bufferDraw",
    0x88: "bulletIndex",
    0x89: "dangerTickCount",
    0x8a: "dangerTickIdx",
    0x8b: "moveHorz",
    0x8c: "moveVert",
    0x8d: "updateHUD",
    0x8e: "flipFlop",
    0x8f: "backLayer",
    0x90: "enemyHit",
    0x91: "enemyHitType",
    0x92: "lastInput",
    0x93: "pause",
    0x94: "fireCoolDown",
    0x95: "pathPos",
    0x96: "audioMask",
    0x97: "audioFrame",
    0x98: "audioExplFrame",
}
for addr, name in zero_page.items():
    label(addr, name)
# (The bytes after the first of zWorldPtr and tempBlock, which are 2 and 22
# bytes long, whose uses would otherwise get Applesoft's names for them)
expr_label(0x51, "zWorldPtr+1")
for i in range(1, 22):
    expr_label(0x56 + i, "tempBlock+%d" % i)

# The loader jumps here
entry(0x6000)
go()
