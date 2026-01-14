
CREATE TABLE flag(f TEXT);
CREATE TABLE flag_chars(C INTEGER, IDX INTEGER);

INSERT INTO flag VALUES('maple{fake_flag}');

WITH
explode(s, i) AS (
  SELECT SUBSTR((SELECT f FROM flag LIMIT 1), 1, 1), 1
  UNION ALL
  SELECT SUBSTR((SELECT f FROM flag LIMIT 1), i+1, 1), i+1 FROM explode
  WHERE i < LENGTH((SELECT f FROM flag LIMIT 1))
) 
INSERT INTO flag_chars (C, IDX) 
SELECT UNICODE(s), i FROM explode;
WITH
conquer AS (
    SELECT 'win :)' FROM flag_chars
),
vanquish AS (
    SELECT 'lose :(' FROM flag_chars
),
c1 AS (
    SELECT c FROM flag_chars WHERE IDX = 1
),
c2 AS (
    SELECT c FROM flag_chars WHERE IDX = 2
),
c3 AS (
    SELECT c FROM flag_chars WHERE IDX = 3
),
c4 AS (
    SELECT c FROM flag_chars WHERE IDX = 4
),
c5 AS (
    SELECT c FROM flag_chars WHERE IDX = 5
),
c6 AS (
    SELECT c FROM flag_chars WHERE IDX = 6
),
c7 AS (
    SELECT c FROM flag_chars WHERE IDX = 7
),
c8 AS (
    SELECT c FROM flag_chars WHERE IDX = 8
),
c9 AS (
    SELECT c FROM flag_chars WHERE IDX = 9
),
c10 AS (
    SELECT c FROM flag_chars WHERE IDX = 10
),
c11 AS (
    SELECT c FROM flag_chars WHERE IDX = 11
),
c12 AS (
    SELECT c FROM flag_chars WHERE IDX = 12
),
c13 AS (
    SELECT c FROM flag_chars WHERE IDX = 13
),
c14 AS (
    SELECT c FROM flag_chars WHERE IDX = 14
),
c15 AS (
    SELECT c FROM flag_chars WHERE IDX = 15
),
c16 AS (
    SELECT c FROM flag_chars WHERE IDX = 16
),
c17 AS (
    SELECT c FROM flag_chars WHERE IDX = 17
),
c18 AS (
    SELECT c FROM flag_chars WHERE IDX = 18
),
c19 AS (
    SELECT c FROM flag_chars WHERE IDX = 19
),
c20 AS (
    SELECT c FROM flag_chars WHERE IDX = 20
),
c21 AS (
    SELECT c FROM flag_chars WHERE IDX = 21
),
c22 AS (
    SELECT c FROM flag_chars WHERE IDX = 22
),
c23 AS (
    SELECT c FROM flag_chars WHERE IDX = 23
),
c24 AS (
    SELECT c FROM flag_chars WHERE IDX = 24
),
c25 AS (
    SELECT c FROM flag_chars WHERE IDX = 25
),
c26 AS (
    SELECT c FROM flag_chars WHERE IDX = 26
),
c27 AS (
    SELECT c FROM flag_chars WHERE IDX = 27
),
c28 AS (
    SELECT c FROM flag_chars WHERE IDX = 28
),
c29 AS (
    SELECT c FROM flag_chars WHERE IDX = 29
),
c30 AS (
    SELECT c FROM flag_chars WHERE IDX = 30
),
c31 AS (
    SELECT c FROM flag_chars WHERE IDX = 31
),
c32 AS (
    SELECT c FROM flag_chars WHERE IDX = 32
),
c33 AS (
    SELECT c FROM flag_chars WHERE IDX = 33
),
c34 AS (
    SELECT c FROM flag_chars WHERE IDX = 34
),
c35 AS (
    SELECT c FROM flag_chars WHERE IDX = 35
),
c36 AS (
    SELECT c FROM flag_chars WHERE IDX = 36
),
c37 AS (
    SELECT c FROM flag_chars WHERE IDX = 37
),
c38 AS (
    SELECT c FROM flag_chars WHERE IDX = 38
),
c39 AS (
    SELECT c FROM flag_chars WHERE IDX = 39
),
c40 AS (
    SELECT c FROM flag_chars WHERE IDX = 40
),
c41 AS (
    SELECT c FROM flag_chars WHERE IDX = 41
),
c42 AS (
    SELECT c FROM flag_chars WHERE IDX = 42
),
g1 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c1 LIMIT 1) - (SELECT * FROM c7 LIMIT 1)) = 10
        THEN (SELECT * FROM g2)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g2 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c2 LIMIT 1) - (SELECT * FROM c8 LIMIT 1)) = -19
        THEN (SELECT * FROM g3)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g3 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c3 LIMIT 1) - (SELECT * FROM c9 LIMIT 1)) = 11
        THEN (SELECT * FROM g4)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g4 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c4 LIMIT 1) - (SELECT * FROM c10 LIMIT 1)) = -7
        THEN (SELECT * FROM g5)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g5 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c5 LIMIT 1) - (SELECT * FROM c11 LIMIT 1)) = 6
        THEN (SELECT * FROM g6)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g6 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c6 LIMIT 1) - (SELECT * FROM c12 LIMIT 1)) = 18
        THEN (SELECT * FROM g7)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g7 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c7 LIMIT 1) - (SELECT * FROM c13 LIMIT 1)) = -11
        THEN (SELECT * FROM g8)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g8 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c8 LIMIT 1) - (SELECT * FROM c14 LIMIT 1)) = 21
        THEN (SELECT * FROM g9)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g9 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c9 LIMIT 1) - (SELECT * FROM c15 LIMIT 1)) = -14
        THEN (SELECT * FROM g10)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g10 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c10 LIMIT 1) - (SELECT * FROM c16 LIMIT 1)) = 2
        THEN (SELECT * FROM g11)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g11 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c11 LIMIT 1) - (SELECT * FROM c17 LIMIT 1)) = -13
        THEN (SELECT * FROM g12)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g12 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c12 LIMIT 1) - (SELECT * FROM c18 LIMIT 1)) = 10
        THEN (SELECT * FROM g13)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g13 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c13 LIMIT 1) - (SELECT * FROM c19 LIMIT 1)) = 10
        THEN (SELECT * FROM g14)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g14 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c14 LIMIT 1) - (SELECT * FROM c20 LIMIT 1)) = -10
        THEN (SELECT * FROM g15)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g15 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c15 LIMIT 1) - (SELECT * FROM c21 LIMIT 1)) = 0
        THEN (SELECT * FROM g16)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g16 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c16 LIMIT 1) - (SELECT * FROM c22 LIMIT 1)) = -3
        THEN (SELECT * FROM g17)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g17 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c17 LIMIT 1) - (SELECT * FROM c23 LIMIT 1)) = 3
        THEN (SELECT * FROM g18)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g18 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c18 LIMIT 1) - (SELECT * FROM c24 LIMIT 1)) = -15
        THEN (SELECT * FROM g19)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g19 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c19 LIMIT 1) - (SELECT * FROM c25 LIMIT 1)) = 1
        THEN (SELECT * FROM g20)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g20 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c20 LIMIT 1) - (SELECT * FROM c26 LIMIT 1)) = -11
        THEN (SELECT * FROM g21)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g21 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c21 LIMIT 1) - (SELECT * FROM c27 LIMIT 1)) = 7
        THEN (SELECT * FROM g22)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g22 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c22 LIMIT 1) - (SELECT * FROM c28 LIMIT 1)) = -5
        THEN (SELECT * FROM g23)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g23 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c23 LIMIT 1) - (SELECT * FROM c29 LIMIT 1)) = 10
        THEN (SELECT * FROM g24)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g24 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c24 LIMIT 1) - (SELECT * FROM c30 LIMIT 1)) = 6
        THEN (SELECT * FROM g25)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g25 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c25 LIMIT 1) - (SELECT * FROM c31 LIMIT 1)) = -18
        THEN (SELECT * FROM g26)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g26 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c26 LIMIT 1) - (SELECT * FROM c32 LIMIT 1)) = 2
        THEN (SELECT * FROM g27)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g27 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c27 LIMIT 1) - (SELECT * FROM c33 LIMIT 1)) = -8
        THEN (SELECT * FROM g28)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g28 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c28 LIMIT 1) - (SELECT * FROM c34 LIMIT 1)) = 26
        THEN (SELECT * FROM g29)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g29 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c29 LIMIT 1) - (SELECT * FROM c35 LIMIT 1)) = -14
        THEN (SELECT * FROM g30)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g30 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c30 LIMIT 1) - (SELECT * FROM c36 LIMIT 1)) = -17
        THEN (SELECT * FROM g31)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g31 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c31 LIMIT 1) - (SELECT * FROM c37 LIMIT 1)) = 22
        THEN (SELECT * FROM g32)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g32 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c32 LIMIT 1) - (SELECT * FROM c38 LIMIT 1)) = 10
        THEN (SELECT * FROM g33)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g33 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c33 LIMIT 1) - (SELECT * FROM c39 LIMIT 1)) = 15
        THEN (SELECT * FROM g34)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g34 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c34 LIMIT 1) - (SELECT * FROM c40 LIMIT 1)) = -2
        THEN (SELECT * FROM g35)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g35 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c35 LIMIT 1) - (SELECT * FROM c41 LIMIT 1)) = 9
        THEN (SELECT * FROM g36)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
),
g36 AS (
    SELECT
    CASE 
      WHEN ((SELECT * FROM c36 LIMIT 1) - (SELECT * FROM c42 LIMIT 1)) = -4
        THEN (SELECT * FROM conquer)
      ELSE (SELECT * FROM vanquish)
    END FROM flag_chars LIMIT 1
)
SELECT * FROM g1;