---
layout: post
title: "[UTCTF 2021] smol data"
author: ko
---

# smol data

The question supplies a 10,000 row .csv and the line "Can you review this attendance data to find the impostors before all the lines are squared?", implying that this is solvable by training a model using the least squares error
The 71st column has the header 'name' and contains letters/braces, so you can ignore this column and use it later to generate the flag, its useless in training a model.
To massage the data into a form we can use to train a model, we loading them into python using NumPy. Then, cut apart the variables from the data set to create an matrix from the 0:68 index columns, and a column vector from the 69 index column. Using these, you can train a linear regression model from scikit learn's linear model package.

```py
data = np.genfromtxt('anomaly_detect_without_name.csv',delimiter=',')
X = data[:,0:69]
y = data[:,69]

reg = linear_model.LinearRegression()
reg.fit(X,y)
prd = reg.predict(X)
```

Generate the predictions, and calculate the least squares error of the predictions by subtracting the predictions from the training data. To learn more about the structure of the data and the model, you can then retrieve the median, mean, and standard deviation. 

```py
sqr = np.square(y - prd)
std = np.std(sqr)
```

With this information, you can finally find the outliers. To find the flag, we first looked at points with least squares errors outside of 3 standard deviations. Printing the corresponding letters in the 'name' column, the response shows this is clearly close, but too rigid of a boundary: ulagmCh1E_r_UxLFa000}.
Clearly some outliers are closer, so can set up a loop to test multiple boundaries for classifying an outlier to see which produces a flag.

```py
datafile = open('anomaly_detect.csv', 'r')
datareader = csv.reader(datafile, delimiter=',')
data = []
for row in datareader:
    data.append(row) 

for i in range(10):
    locs = np.argwhere(sqr > ((0.002 * i)) * np.std(sqr))
    locs2 = locs + 1
    a, b = locs.shape
    locs3 = locs2.reshape(b,a)[0]
    if len(locs3) < 100:
        for i in locs3:
            print(data[i][70], end="")  
    print()
```

Doing this you find the flag with errors greater than around 0.01*std:
utflag{m4Ch1nE_1rNg_SUx_LMFa0000000}