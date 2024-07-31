// https://github.com/phenomLi/Blog/issues/24

const listOld = ["A", "B", "C", "D"];
const listNew = ["B", "A", "D", "C",]


/**
 * 从旧数组变成新数组，需要的最小的操作数。操作：移动某个元素，插入某个元素，删除某个元素
 * @param {string[]} listOld 
 * @param {string[]} listNew 
 */
function listDiff(listOld, listNew) {
  let lastIndex = 0;
  for (let i = 0; i < listNew.length; i++) {
    const element = listNew[i];
    const oldIndex = listOld.indexOf(element);
    if (oldIndex > -1) {
      // 说明元素存在，再判断是否需要移动
      if (lastIndex > oldIndex) {
        // 新数组前面的元素的在旧数组中做大索引 大于 当前元素在旧数组中的索引，需要移动
        move(listOld, element, oldIndex, i);
      }
      lastIndex = Math.max(lastIndex, oldIndex);
    }  else {
      // 说明元素不存在，需要插入新元素
      insert(element);
    }
  }
}

/**
 * 
 * @param {string} element 
 * @param {number} targetIndex 
 */
function insert(element, targetIndex) {
  console.log(`插入元素：${element} 到位置: ${targetIndex}`);
}

/**
 * 
 * @param {string[]} list 
 * @param {string} element 
 * @param {number} fromIndex 
 * @param {numbere} toIndex 
 */
function move(list, element, fromIndex, toIndex) {
  console.log(`移动元素：${element} 从${fromIndex} 到位置: ${toIndex}`);
  list.splice(fromIndex, 1);
  list.splice(toIndex, 0, element);
}

/**
 * 
 * @param {string} element 
 */
function remove(element) {
  console.log("删除元素：", element);
}

listDiff(listOld, listNew);

console.log("after move: ", listOld);