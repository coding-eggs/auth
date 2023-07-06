package com.coding.auth.utils;

import lombok.Getter;

import java.util.*;

@Getter
public class RandomCodeVerifier {


    private static final Random r = new Random();

    private static final char[] lowerChar = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
    private static final char[] upperChar = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
    private static final char[] numberChar = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

    private static final char[] symbolChar = { '.', '-', '_', '~'};

    private static final int MAX_CODE_VERIFIER_LENGTH = 128;

    private static final int MIN_CODE_VERIFIER_LENGTH = 43;


    /**
     * 获取code verifier
     * @return code verifier
     */
    public static String getCodeVerifier() {
        Random random = new Random();
        int i = random.nextInt(MAX_CODE_VERIFIER_LENGTH - MIN_CODE_VERIFIER_LENGTH + 1) + MIN_CODE_VERIFIER_LENGTH;
        return getRandomString(i);
    }

    /**
     * 获取随机字符串，包含大小写字母和数字，可以有重复字符
     *
     * @param strLength 字符串长度
     */
    public static String getRandomString(int strLength) {
        return getRandomString(strLength,  true);
    }

    /**
     * 获取随机字符串
     *
     * @param strLength  字符串长度
     * @param repeat     是否可以有重复字符，true表示可以重复，false表示不允许重复。如果生成字符长度大于可用字符数量则默认采用true值。
     */
    public static String getRandomString(int strLength,  boolean repeat) {
        StringBuilder result = new StringBuilder();
        char[] validChar = null;// 可用字符数组

        validChar = Arrays.copyOf(lowerChar, lowerChar.length + upperChar.length + numberChar.length + symbolChar.length);
        System.arraycopy(upperChar, 0, validChar, lowerChar.length, upperChar.length);
        System.arraycopy(numberChar, 0, validChar, lowerChar.length + upperChar.length, numberChar.length);
        System.arraycopy(symbolChar, 0, validChar, lowerChar.length + upperChar.length + numberChar.length, symbolChar.length);
        if (strLength > validChar.length) {// 字符串长度大于可用字符数量
            repeat = true;// 字符可重复
        }
        if (repeat) {
            for (int i = 0; i < strLength; i++) {
                result.append(validChar[r.nextInt(validChar.length)]);
            }
        } else {
            HashSet<Integer> indexset = new HashSet<Integer>();
            int index = 0;
            for (int i = 0; i < strLength; i++) {
                do {
                    index = r.nextInt(validChar.length);// 随机获得一个字符的索引
                } while (indexset.contains(index));// 如果已经使用过了，则重新获得
                result.append(validChar[index]);
                indexset.add(index);// 记录已使用的字符索引
            }
        }
        return result.toString();
    }

    /**
     * 获取随机字符串
     *
     * @param strLength 字符串长度
     * @param repeat    是否可以存在重复的字符
     * @param ch        自定义字符集，可传入多个字符数组
     */
    public static String getRandomString(int strLength, boolean repeat, char[]... ch) {
        StringBuilder result = new StringBuilder();
        HashSet<Character> validChar = new HashSet<>();
        for (char[] chars : ch) {
            for (char aChar : chars) {
                validChar.add(aChar);
            }
        }
        if (validChar.isEmpty()) {
            return "";
        }
        if (strLength > validChar.size()) {// 字符串长度大于可用字符数量
            repeat = true;// 字符可重复
        }
        List<Character> list = new LinkedList<>(validChar);
        for (int i = 0; i < strLength; i++) {
            if (repeat) {
                result.append(list.get(r.nextInt(list.size())));
            } else {
                result.append(list.remove(r.nextInt(list.size())));
            }
        }
        return result.toString();
    }


}
